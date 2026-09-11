<?php
defined('ABSPATH') || exit;

/**
 * Atomic, InnoDB-lock-based rate-limit counter used exclusively by
 * ChargeGuard_Dynamic_Firewall::resolve_api_unavailable_decision() to
 * bound how many checkout attempts a single IP can push through while
 * the ChargeGuard risk-scoring API is unreachable (circuit breaker open,
 * or a single failed/5xx request — see that method's docblock).
 *
 * PROBLEM THIS REPLACES (TOCTOU): the previous implementation used
 * get_transient()/set_transient() as a read-increment-write pair:
 *   $count = (int) get_transient($key);
 *   $count++;
 *   set_transient($key, $count, $window);
 * Under concurrency — which is exactly the condition an attacker
 * exploiting an API outage would create, by definition sending many
 * requests at once — two or more PHP processes can read the same stale
 * $count before either has written its increment back, silently losing
 * increments. This is precisely the scenario ChargeGuard exists to
 * defend against, so a rate limiter that can under-count under load is
 * a real security gap, not a cosmetic bug.
 *
 * FIX: a single atomic SQL statement (INSERT ... ON DUPLICATE KEY
 * UPDATE) against wp_options, relying on two facts verified directly
 * against this project's database before writing this class:
 *   - wp_options uses the InnoDB storage engine (confirmed via
 *     SHOW CREATE TABLE wp_options), so this statement takes a real
 *     row-level lock, not a table-level lock.
 *   - wp_options.option_name has a UNIQUE KEY (confirmed via the same
 *     check), which is what makes "ON DUPLICATE KEY UPDATE" apply to
 *     the correct row instead of silently inserting a duplicate.
 * MySQL serializes concurrent INSERT ... ON DUPLICATE KEY UPDATE
 * statements against the same key, so every increment is guaranteed to
 * be observed by every subsequent one — no lost updates.
 *
 * WHY wp_options AND NOT A DEDICATED TABLE: this mirrors exactly where
 * WordPress transients (the mechanism being replaced) already stored
 * this same data by default — wp_options — so no new table/dbDelta()
 * migration is introduced for what is still, conceptually, a transient
 * counter. See cleanup_stale_buckets() below for how this class avoids
 * the unbounded-growth trade-off of leaving transient expiry behind.
 *
 * WHY A FIXED WINDOW BUCKET IN THE KEY: rather than storing one mutable
 * counter and racing over when to reset it (which reintroduces a TOCTOU
 * on the reset step itself), each increment() call is scoped to the
 * current window's bucket via a key suffix — see bucket_key(). A new
 * window is simply a new row; nothing is ever reset. The trade-off is
 * that old buckets are inert rows left behind once their window has
 * passed — cleanup_stale_buckets() removes those on a schedule (wired
 * up in chargeguard-woocommerce.php).
 */
class ChargeGuard_Atomic_Rate_Limiter {

    /**
     * How long past its own bucket window a row is left in wp_options
     * before cleanup_stale_buckets() considers it safe to delete.
     *
     * Deliberately NOT tied to the caller's $window value (filterable
     * via chargeguard_api_down_rate_limit_window, and not known to this
     * class ahead of a given call) — this is a generous, fixed upper
     * bound instead. The shipped default window
     * (ChargeGuard_Dynamic_Firewall::API_DOWN_RATE_LIMIT_WINDOW) is 300s
     * / 5 minutes; a full day of retention margin means cleanup can
     * never race a bucket that's still legitimately in use, at the cost
     * of stale rows sticking around up to ~1 extra day in the
     * (expected-rare) worst case.
     */
    const BUCKET_STALE_AFTER_SECONDS = DAY_IN_SECONDS;

    /**
     * Max stale option rows deleted per cleanup run, so a store that had
     * a very large/prolonged outage (many distinct IPs, many buckets)
     * can't turn one cron tick into one enormous DELETE burst. Any
     * remainder is simply picked up on the next scheduled run.
     */
    const CLEANUP_BATCH_SIZE = 500;

    /**
     * Atomically increments the counter for $key within the current
     * $window-second bucket and returns the count AFTER this increment
     * — this call's own attempt is always included, and so is every
     * concurrent increment that happened to commit first.
     *
     * @param string $key    Caller-supplied key prefix — e.g.
     *                        ChargeGuard_Dynamic_Firewall::API_DOWN_RATE_LIMIT_TRANSIENT_PREFIX
     *                        . md5($ip). This class appends the window
     *                        bucket suffix internally (see bucket_key());
     *                        callers must NOT do this themselves.
     * @param int    $window Window length in seconds. Must be positive;
     *                        see the defensive fallback below.
     * @return int The post-increment count for this key's current
     *              bucket. On any database failure, returns PHP_INT_MAX
     *              rather than 0 or a stale count — see the fail-closed
     *              rationale below.
     */
    public static function increment($key, $window) {
        global $wpdb;

        $key    = (string) $key;
        $window = (int) $window;

        if ($key === '') {
            error_log('ChargeGuard_Atomic_Rate_Limiter::increment() called with an empty key — refusing to guess a bucket, failing closed.');
            return PHP_INT_MAX;
        }
        if ($window <= 0) {
            // Defensive fallback only — resolve_api_unavailable_decision()
            // always passes a positive, filtered window, but a
            // misconfigured filter (chargeguard_api_down_rate_limit_window)
            // returning 0 or negative must not divide-by-zero below or
            // produce a bucket that never rotates.
            error_log('ChargeGuard_Atomic_Rate_Limiter::increment() called with a non-positive window (' . $window . ') — falling back to 300s.');
            $window = 300;
        }

        $option_name = self::bucket_key($key, $window);

        // LAST_INSERT_ID(expr) is what makes this ONE atomic round trip
        // instead of "INSERT/UPDATE, then a separate SELECT to see the
        // new value" — which would itself reintroduce a race between the
        // write and the read. Wrapping the assigned value in
        // LAST_INSERT_ID(...) on BOTH the insert branch and the update
        // branch tells MySQL to report that value back via
        // $wpdb->insert_id, overriding wp_options' own unrelated
        // auto-increment option_id column for this statement only. This
        // is a standard, well-established MySQL idiom for atomic
        // counters on a table that already has its own auto-increment
        // primary key.
        //
        // autoload is explicitly 'no': these rows must never be pulled
        // into WordPress's autoloaded-options cache that loads on every
        // single page request — the opposite of where a fast-churning,
        // per-IP, per-window counter belongs.
        $sql = "INSERT INTO {$wpdb->options} (option_name, option_value, autoload)
                VALUES (%s, LAST_INSERT_ID(1), 'no')
                ON DUPLICATE KEY UPDATE option_value = LAST_INSERT_ID(option_value + 1)";

        $result = $wpdb->query($wpdb->prepare($sql, $option_name));

        if ($result === false) {
            // Fail CLOSED, deliberately: this counter only ever runs once
            // the main ChargeGuard API is already unreachable — it's the
            // last line of defense. Returning 0 (or a stale count) on a
            // DB error would silently disable rate limiting during
            // exactly the window when the store has the least protection
            // left. PHP_INT_MAX guarantees the caller's
            // `if ($count > $limit)` check blocks the request instead —
            // a false-positive block on one legitimate customer during a
            // simultaneous DB+API outage is a recoverable cost; a silent
            // bypass during a card-testing burst is not.
            error_log('ChargeGuard_Atomic_Rate_Limiter::increment() failed — ' . $wpdb->last_error . ' — failing closed (treating as over limit).');
            return PHP_INT_MAX;
        }

        $count = (int) $wpdb->insert_id;
        if ($count <= 0) {
            // Should not happen given the query always assigns a positive
            // value via LAST_INSERT_ID(), but guard against a driver/proxy
            // layer that doesn't propagate insert_id correctly rather than
            // silently returning a bogus count to the caller.
            error_log('ChargeGuard_Atomic_Rate_Limiter::increment() got an unexpected non-positive insert_id — failing closed (treating as over limit).');
            return PHP_INT_MAX;
        }

        return $count;
    }

    /**
     * Builds the fixed-window bucket key for $key: the base key suffixed
     * with the window's start timestamp (not a sequential bucket index),
     * so cleanup_stale_buckets() can tell how old an abandoned bucket is
     * purely by parsing its own option_name — no separate "created at"
     * column or lookup table needed.
     *
     * @param string $key
     * @param int    $window
     * @return string
     */
    private static function bucket_key($key, $window) {
        $bucket_start = (int) (floor(time() / $window) * $window);
        return $key . '_' . $bucket_start;
    }

    /**
     * Deletes stale bucket rows left behind in wp_options once their
     * window has long since passed. Without this, every distinct
     * (IP, window) pair ever seen during an API outage stays in
     * wp_options forever — the exact unbounded-growth problem this class
     * was written to move away from (see MAX_BLACKLIST_SIZE's docblock
     * in class-dynamic-firewall.php for the same concern applied
     * elsewhere in this plugin) would simply resurface one layer up.
     *
     * This class only provides the callback — it is registered as an
     * hourly WP-Cron job in chargeguard-woocommerce.php, matching the
     * existing chargeguard_cleanup_stale_drafts / chargeguard_refresh_cf_ranges
     * pattern (activation/deactivation hooks live in the main plugin
     * file, not inside the class).
     *
     * Batched and self-limiting (see CLEANUP_BATCH_SIZE): a run that
     * hits the cap simply leaves the remainder for the next scheduled
     * run rather than issuing one unbounded DELETE.
     */
    public static function cleanup_stale_buckets() {
        global $wpdb;

        $prefix = $wpdb->esc_like(ChargeGuard_Dynamic_Firewall::API_DOWN_RATE_LIMIT_TRANSIENT_PREFIX) . '%';

        $option_names = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT %d",
                $prefix,
                self::CLEANUP_BATCH_SIZE
            )
        );

        if (empty($option_names)) {
            return;
        }

        $now     = time();
        $deleted = 0;

        foreach ($option_names as $option_name) {
            // The bucket start timestamp is the final underscore-delimited
            // segment (see bucket_key()) — anything that doesn't parse as
            // one is left alone rather than guessed at.
            if (!preg_match('/_(\d+)$/', $option_name, $matches)) {
                continue;
            }
            $bucket_start = (int) $matches[1];
            if (($now - $bucket_start) > self::BUCKET_STALE_AFTER_SECONDS) {
                delete_option($option_name);
                $deleted++;
            }
        }

        if ($deleted > 0) {
            error_log('ChargeGuard_Atomic_Rate_Limiter: cleaned up ' . $deleted . ' stale rate-limit bucket(s).');
        }
    }
}