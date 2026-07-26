<?php
/**
 * ChargeGuard - Dynamic Firewall
 *
 * يمنع الأجهزة المحظورة من الوصول إلى صفحة الدفع،
 * ويضيف طبقة حماية عبر رمز جلسة آمنة.
 *
 * TRUST BOUNDARY WARNING: chargeguard_fp is generated entirely by
 * client-side JavaScript (assets/js/chargeguard-firewall.js) and is
 * never signed or verified by the server. Any value read from
 * $_COOKIE['chargeguard_fp'] (or the equivalent 'fingerprint' POST
 * field in ajax_check_fingerprint()) must be treated as
 * attacker-controlled input, not a trustworthy device identity. A
 * visitor can set this cookie to any string via the browser console,
 * or simply clear cookies to get a brand-new fingerprint on the next
 * page load. The local blacklist checks in this file (see
 * check_device_blacklist(), intercept_checkout(),
 * intercept_checkout_block()) are therefore a fast, cheap first-line
 * heuristic only — never the sole basis for a security decision.
 * evaluate_risk() (the cloud API call) is the authoritative check; do
 * not remove or weaken it in favor of the local blacklist, and do not
 * present a local-blacklist block to merchants as a hard guarantee.
 * See includes/class-admin-settings.php for the merchant-facing
 * explanation of this limitation.
 *
 * @package ChargeGuard_WooCommerce
 */

defined('ABSPATH') || exit;

class ChargeGuard_Blocked_Exception extends \Exception {}

class ChargeGuard_Dynamic_Firewall {

    /**
     * عميل API للتواصل مع ChargeGuard.
     *
     * @var ChargeGuard_API_Client|null
     */
    private $api_client;

    /**
     * اسم الخيار في قاعدة البيانات لتخزين القائمة السوداء المحلية.
     *
     * @var string
     */
    private $blacklist_option = 'chargeguard_device_blacklist';

    /**
     * Hard cap on the number of entries kept in the local device
     * blacklist option. Without this, a card-testing attack — the exact
     * scenario this plugin exists to defend against — can add thousands
     * of blocked fingerprints within a single block-duration window,
     * turning what should be a fast, cheap pre-checkout heuristic into
     * an unbounded, growing blob that every legitimate checkout page
     * load has to deserialize, scan, and (on prune) write back in full.
     * See add_device_to_blacklist() for the eviction logic this backs.
     *
     * This is a pre-launch, low-risk safety net on top of the existing
     * option-based storage — not a replacement for it. A dedicated
     * indexed table (see audit finding) remains the correct longer-term
     * architecture and is tracked as a follow-up.
     */
    const MAX_BLACKLIST_SIZE = 500;

    /**
     * Merchant-configurable behavior when evaluate_risk() cannot reach the
     * backend — whether because the circuit breaker is open, or because a
     * single request failed/5xx'd (both mean "no authoritative decision is
     * available" and are handled identically; see
     * resolve_api_unavailable_decision()).
     *
     *   block_all    — fail-closed: no order proceeds while the API is down.
     *   local_checks — semi-open (DEFAULT): local device blacklist + a hard
     *                  per-IP rate limit that is only ever incremented while
     *                  the API is unreachable. Anything that clears both is
     *                  approved but flagged as degraded/unscored.
     *   allow_all    — legacy behavior (approve everything). Only takes
     *                  effect if API_DOWN_ALLOW_ALL_ACK_OPTION is also '1' —
     *                  see resolve_api_unavailable_decision().
     */
    const API_DOWN_BEHAVIOR_OPTION      = 'chargeguard_api_down_behavior';
    const API_DOWN_ALLOW_ALL_ACK_OPTION = 'chargeguard_api_down_allow_all_ack';
    const API_DOWN_RATE_LIMIT_OPTION    = 'chargeguard_api_down_rate_limit';
    const API_DOWN_RATE_LIMIT_TRANSIENT_PREFIX = 'cg_apidown_ip_';
    const API_DOWN_RATE_LIMIT_WINDOW    = 300; // 5 minutes
    const API_DOWN_RATE_LIMIT_DEFAULT_MAX = 3;
    const API_DOWN_STATUS_OPTION        = 'chargeguard_api_down_status';

    /**
     * Resolve the visitor's IP address.
     *
     * By default (chargeguard_trust_proxy_headers = 0) this ALWAYS returns
     * REMOTE_ADDR — the one value a client cannot spoof, since it comes from
     * the TCP connection itself rather than any HTTP header. Only when the
     * merchant has explicitly confirmed (in ChargeGuard settings) that the
     * site sits behind a trusted reverse proxy/CDN do we consider forwarded
     * headers, because HTTP_X_FORWARDED_FOR / HTTP_CF_CONNECTING_IP are
     * ordinary request headers that any client can set directly unless a
     * proxy in front of the origin is guaranteed to overwrite them.
     *
     * When trusted-proxy mode is on:
     *   1. CF-Connecting-IP — set exclusively by Cloudflare on every proxied
     *      request; preferred over generic X-Forwarded-For when present.
     *   2. WC_Geolocation::get_ip_address() — WooCommerce core's header
     *      parser (X-Real-IP, then X-Forwarded-For first-hop, then
     *      REMOTE_ADDR), reused here for its battle-tested parsing/
     *      validation rather than reimplementing header-chain parsing.
     *   3. REMOTE_ADDR — final fallback if neither header is present.
     *
     * This method is the single source of truth for IP resolution in this
     * plugin; class-admin-settings.php's "add my IP" feature must use the
     * exact same logic or the two will disagree about what a visitor's IP
     * is.
     *
     * @return string
     */
    public static function get_client_ip() {
    $mode = get_option( ChargeGuard_Trusted_Proxy::PROXY_MODE_OPTION, null );

    // Backward compat: existing installs have chargeguard_trust_proxy_headers
    // but not the new mode option yet. Map the old boolean onto the new
    // scheme ONCE via this fallback so already-configured stores keep
    // working unchanged — they land in 'both' (the old behavior's superset)
    // rather than being silently reset to 'off'.
    if ( $mode === null ) {
        $mode = get_option( 'chargeguard_trust_proxy_headers', 0 ) ? 'both' : 'off';
    }

    $remote_addr = isset( $_SERVER['REMOTE_ADDR'] )
        ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
        : '';

    if ( $mode === 'off' || $remote_addr === '' ) {
        return $remote_addr;
    }

    // --- Cloudflare path: header is only trusted if REMOTE_ADDR (the
    // actual TCP peer) is verified to be a Cloudflare edge IP. This is
    // the fix for the toggle-on-but-unverified gap: presence/format of
    // CF-Connecting-IP is no longer sufficient on its own. ---
    if ( in_array( $mode, [ 'cloudflare', 'both' ], true )
        && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] )
        && ChargeGuard_Trusted_Proxy::ip_in_any_cidr( $remote_addr, ChargeGuard_Trusted_Proxy::get_cf_ranges() )
    ) {
        $cf_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        if ( rest_is_ip_address( $cf_ip ) ) {
            return $cf_ip;
        }
    }

    // --- Generic reverse proxy path: X-Forwarded-For (via WC_Geolocation's
    // parser) is only trusted if REMOTE_ADDR is in the merchant's
    // configured trusted-proxy CIDR list. No more "trust any hop simply
    // because the toggle is on." ---
    if ( in_array( $mode, [ 'custom', 'both' ], true ) ) {
        $trusted_cidrs = ChargeGuard_Trusted_Proxy::get_custom_proxy_cidrs();
        if ( ! empty( $trusted_cidrs )
            && ChargeGuard_Trusted_Proxy::ip_in_any_cidr( $remote_addr, $trusted_cidrs )
            && class_exists( 'WC_Geolocation' )
        ) {
            $wc_ip = WC_Geolocation::get_ip_address();
            if ( ! empty( $wc_ip ) ) {
                return $wc_ip;
            }
        }
    }

    return $remote_addr;
}

    

    /**
     * The throwaway pre-order ID generated by intercept_checkout() for the
     * current classic-checkout request, carried forward so it can be sent
     * to the backend once the real order ID exists. Classic checkout only
     * — Blocks checkout uses the real order ID from the start (see
     * intercept_checkout_block()) and never needs this.
     *
     * @var string|null
     */
    private $pre_order_id = null;

    /**
     * The device fingerprint captured by intercept_checkout() for the
     * current classic-checkout request, carried forward the same way as
     * $pre_order_id so it can be persisted as order meta once the real
     * order exists (see reconcile_pre_order_id()). This is what lets the
     * Stripe/PayPal webhook handlers — which never see the checkout-time
     * fingerprint cookie themselves — know which device to blacklist on a
     * post-payment block or lost-dispute decision.
     *
     * @var string|null
     */
    private $pre_device_fp = null;

    /**
     * The server-signed device token (chargeguard_dt cookie) captured by
     * intercept_checkout() for the current classic-checkout request,
     * carried forward the same way as $pre_device_fp so it can be
     * persisted as order meta once the real order exists (see
     * reconcile_pre_order_id()). Blocks checkout doesn't need this — it
     * persists the token directly in intercept_checkout_block() since it
     * already has a real order at that point.
     *
     * @var string|null
     */
    private $pre_device_token = null;

    /**
     * تهيئة الخطافات المطلوبة.
     */
    public function __construct() {
        // احترام إعدادات التفعيل
        if (!get_option('chargeguard_enable_firewall', 1)) {
            return;
        }
        if (defined('CHARGEGUARD_DEBUG') && CHARGEGUARD_DEBUG) {
            error_log('ChargeGuard Dynamic Firewall loaded');
        }

        // تحميل عميل API إن كان موجودًا
        if (class_exists('ChargeGuard_API_Client')) {
            $this->api_client = new ChargeGuard_API_Client();
        }

        // 2. طبقة البصمة
        add_action('wp_enqueue_scripts', [$this, 'enqueue_firewall_assets']);
        add_action('woocommerce_before_checkout_form', [$this, 'handle_checkout_access']);

        // 3. Ajax للفحص
        add_action('wp_ajax_chargeguard_check_fp', [$this, 'ajax_check_fingerprint']);
        add_action('wp_ajax_nopriv_chargeguard_check_fp', [$this, 'ajax_check_fingerprint']);

        // 4. خطاف لتسجيل بصمة ضارة
        add_action('chargeguard_mark_device_fraud', [$this, 'add_device_to_blacklist']);
        add_action('admin_notices', [$this, 'maybe_show_quota_exceeded_notice']);
        add_action('admin_notices', [$this, 'maybe_show_api_down_notice']);

        // 4a. Webhook-path quota detection. The order.created webhook is
        // delivered by WooCommerce core's WC_Webhook::deliver() — not by
        // this plugin — so intercept_checkout()/intercept_checkout_block()
        // never see its response. woocommerce_webhook_delivery is the only
        // point where this plugin's PHP can inspect that response body.
        add_action('woocommerce_webhook_delivery', [$this, 'maybe_flag_webhook_quota_exceeded'], 10, 5);

        // 4b. Server-signed device token — issued as an HttpOnly cookie the
        // client's own JavaScript cannot read or overwrite. See
        // maybe_issue_device_token() below.
        add_action('template_redirect', [$this, 'maybe_issue_device_token']);

        // 5. فحص المخاطر قبل معالجة الطلب
        add_action('woocommerce_checkout_process', [$this, 'intercept_checkout']);
        add_action('woocommerce_store_api_checkout_update_order_from_request', [$this, 'intercept_checkout_block'], 10, 2);

        // 6. ربط تقييم ما قبل الطلب (Classic checkout فقط) بمعرف الطلب الحقيقي
        // بمجرد إنشائه، حتى تستطيع حلقة الـ feedback loop مطابقة النتيجة
        // بالتقييم الأصلي. Blocks checkout لا يحتاج هذا لأنه يستخدم معرف
        // الطلب الحقيقي منذ البداية.
        add_action('woocommerce_checkout_order_created', [$this, 'reconcile_pre_order_id']);
    }

    // ─────────────────────────────────────────────
    // 2. طبقة البصمة (Device Fingerprint)
    // ─────────────────────────────────────────────

    /**
     * تحميل ملفات JavaScript الخاصة بالبصمة على صفحة الدفع فقط.
     */
    public function enqueue_firewall_assets() {
        if (!is_checkout()) {
            return;
        }

        wp_enqueue_script(
            'chargeguard-firewall',
            plugin_dir_url(__FILE__) . '../assets/js/chargeguard-firewall.js',
            ['jquery'],
            defined('CHARGEGUARD_VERSION') ? CHARGEGUARD_VERSION : '1.0.0',
            true
        );

        wp_localize_script('chargeguard-firewall', 'chargeguard_fw', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('chargeguard_fw_nonce'),
        ]);
    }

    /**
     * التحقق من القائمة السوداء قبل عرض صفحة الدفع.
     * إذا كانت البصمة محظورة، يتم منع الوصول.
     */
    public function handle_checkout_access() {
        try {
            $this->check_device_blacklist();
        } catch (ChargeGuard_Blocked_Exception $e) {
            wp_die(
                $e->getMessage(),
                esc_html__('Access Restricted', 'chargeguard-woocommerce'),
                ['response' => 403]
            );
        }
    }

    public function check_device_blacklist() {
        // $_COOKIE['chargeguard_fp'] is client-supplied and unsigned (see
        // the trust-boundary warning at the top of this file) — treat it
        // as untrusted input. sanitize_text_field()/wp_unslash() only
        // guard against XSS/quoting issues, not forgery: a visitor can
        // set this cookie to any string they like.
        if (!isset($_COOKIE['chargeguard_fp'])) {
            return;
        }

        $fingerprint = sanitize_text_field(wp_unslash($_COOKIE['chargeguard_fp']));
        if (empty($fingerprint)) {
            return;
        }

        $this->maybe_log_malformed_fingerprint($fingerprint);

        // الفحص المحلي مع احترام مدة الصلاحية
        $local_blacklist = get_option($this->blacklist_option, []);
        if (is_array($local_blacklist)) {
            // تنظيف تلقائي للحظر المنتهي
            $now = time();
            $changed = false;
            foreach ($local_blacklist as $fp => $expires) {
                if ($expires < $now) {
                    unset($local_blacklist[$fp]);
                    $changed = true;
                }
            }
            if ($changed) {
                update_option($this->blacklist_option, $local_blacklist, false);
            }

            if (isset($local_blacklist[$fingerprint]) && $local_blacklist[$fingerprint] > $now) {
                $this->block_access($fingerprint);
            }
        }

        // M1 fix: the remote check_device() API call was previously made
        // here, on every checkout page GET request (via
        // handle_checkout_access() -> woocommerce_before_checkout_form),
        // adding a blocking network round-trip (up to the client's
        // configured timeout) to every page render. This was redundant
        // for security — intercept_checkout() / intercept_checkout_block()
        // already make the authoritative evaluate_risk() call at order
        // submission time, which is the actual enforcement point — and
        // harmful to performance, since it delayed page load for every
        // returning visitor regardless of risk. Page render now performs
        // only the local, in-process blacklist lookup above; the remote
        // check remains solely at submission time, where it belongs.
    }

    /**
     * Issues a server-signed device token (see
     * ChargeGuard_API_Client::mint_device_token()) and stores it as an
     * HttpOnly cookie, if the current visitor doesn't already have a
     * valid one. Runs on template_redirect (before any output) rather
     * than the later woocommerce_before_checkout_form hook used by
     * check_device_blacklist(), because setcookie() must run before
     * headers are sent.
     *
     * HttpOnly is the entire point: the browser will silently ignore any
     * attempt by page JavaScript to set/overwrite a cookie of this name
     * once it has been marked HttpOnly by the server, so a rotating
     * attacker cannot simply replace this value the way chargeguard_fp
     * can be replaced. A fresh token requires a new, authenticated,
     * signed, rate-limited call to this method.
     *
     * Deliberately never blocks or delays checkout on failure — if the
     * mint call fails (API unreachable, rate-limited, etc.), this
     * silently no-ops and the existing unsigned chargeguard_fp signal is
     * used exactly as before this feature existed. No new fail-open
     * surface: the token is a corroborating signal that raises trust when
     * present and valid, never a requirement whose absence lowers trust
     * below today's baseline.
     */
    public function maybe_issue_device_token() {
        if (!function_exists('is_checkout') || !is_checkout()) {
            return;
        }
        if (!$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }
        if (!empty($_COOKIE['chargeguard_dt'])) {
            return; // Already have one — not proactively rotated on every page view.
        }

        // Rate limit mint attempts per IP. A mint call is a signed,
        // authenticated backend request — without this, repeatedly
        // reloading checkout with cookies blocked/cleared could hammer
        // the mint endpoint. This is a courtesy local limiter; the
        // backend's own deviceTokenRateLimit (see risk.js) is the
        // authoritative one.
        $ip = self::get_client_ip();
        $rl_key   = 'cg_dt_mint_rl_' . md5($ip !== '' ? $ip : 'unknown');
        $rl_count = get_transient($rl_key);
        if ($rl_count !== false && $rl_count >= 10) {
            return; // Silently skip — falls back to the unsigned raw fingerprint only.
        }
        set_transient($rl_key, ($rl_count === false ? 1 : $rl_count + 1), 60);

        $token = $this->api_client->mint_device_token($ip);
        if (is_wp_error($token) || empty($token) || !is_string($token)) {
            return; // Backend unreachable/failed — fall back to unsigned fp, unchanged behavior.
        }

        $secure = is_ssl();
        setcookie('chargeguard_dt', $token, [
            'expires'  => time() + (30 * DAY_IN_SECONDS),
            'path'     => '/',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        // setcookie() only affects the NEXT request — make it available to
        // the rest of THIS request too (mirrors PHP's own superglobal
        // convention), in case a later hook in this same request wants it.
        $_COOKIE['chargeguard_dt'] = $token;
    }

    /**
     * Log-only sanity check: does this fingerprint look like something
     * our own script actually generated (fp2_<64 hex chars> from
     * SHA-256, or fp1_<hex> from the legacy djb2 fallback), or does it
     * look hand-typed (e.g. pasted into the browser console)? This is
     * informational only — it never blocks, and it is intentionally
     * lenient (only flags values that match neither known format) so it
     * can never reject a legitimate visitor on a false positive. It
     * exists purely to give the merchant/support a signal in the error
     * log that someone may be probing the blacklist by hand, not to
     * enforce anything.
     *
     * @param string $fingerprint
     */
    private function maybe_log_malformed_fingerprint($fingerprint) {
        if ($fingerprint === '') {
            return;
        }
        $looks_valid = (bool) preg_match('/^fp2_[0-9a-f]{64}$/', $fingerprint)
            || (bool) preg_match('/^fp1_[0-9a-f]+$/', $fingerprint);

        if (!$looks_valid) {
            error_log('ChargeGuard: received a chargeguard_fp value that does not match either known format (fp2_<sha256> or fp1_<legacy>) — possible manual/forged value: ' . substr($fingerprint, 0, 40));
        }
    }

    /**
     * إضافة بصمة جهاز إلى القائمة السوداء المحلية.
     *
     * @param string $fingerprint بصمة الجهاز.
     */
    public function add_device_to_blacklist($fingerprint) {
        // Defense in depth: call sites already guard against empty/'unknown'
        // fingerprints before firing chargeguard_mark_device_fraud, but this
        // method is a public action callback — anything else that fires the
        // action in the future must not be able to poison the blacklist with
        // a junk key.
        if (empty($fingerprint) || $fingerprint === 'unknown') {
            return;
        }

        $blacklist = get_option($this->blacklist_option, []);
        if (!is_array($blacklist)) {
            $blacklist = [];
        }

        // استخدام مدة الحظر من الإعدادات (بالساعات)
        $duration_hours = (int) get_option('chargeguard_firewall_block_duration', 24);
        $expires_at     = time() + ($duration_hours * 3600);

        // تخزين البصمة مع وقت الانتهاء
        $blacklist[$fingerprint] = $expires_at;

        // Cap enforcement: prevents unbounded growth during a
        // card-testing burst, where thousands of fingerprints can be
        // blocked within a single block-duration window — exactly the
        // scenario that would otherwise turn this option into a large,
        // slow-to-deserialize blob on the checkout hot path. Eviction
        // uses soonest-to-expire-first as a proxy for "oldest"/least
        // recently blocked, since expiry (set at block time + duration)
        // correlates directly with when each entry was added, without
        // needing a separate last-access timestamp. This is purely a
        // size safety net — check_device_blacklist()'s own expiry-based
        // pruning is unchanged and still runs independently.
        if (count($blacklist) > self::MAX_BLACKLIST_SIZE) {
            asort($blacklist); // ascending by expiry timestamp — soonest-to-expire first
            $blacklist = array_slice($blacklist, count($blacklist) - self::MAX_BLACKLIST_SIZE, null, true);
        }

        update_option($this->blacklist_option, $blacklist, false);
    }

    /**
     * Persist a merchant-visible flag when a checkout is blocked due to a
     * plan quota limit rather than an actual fraud decision. Read by
     * maybe_show_quota_exceeded_notice() to render an admin_notices
     * banner — mirrors the existing circuit-breaker / signing-self-test
     * notice pattern already used elsewhere in this plugin.
     *
     * @param string $blocked_reason 'quota_exceeded' or 'pro_quota_exceeded'.
     */
    private function notify_admin_quota_exceeded($blocked_reason) {
        update_option('chargeguard_quota_exceeded_status', [
            'reason'     => $blocked_reason,
            'flagged_at' => time(),
        ], false);

        error_log('ChargeGuard: checkout blocked due to plan quota (' . $blocked_reason . ') — this is a plan limit, not a fraud decision.');
    }

    /**
     * Central fallback decision, called by BOTH intercept_checkout() and
     * intercept_checkout_block() whenever evaluate_risk() returns a
     * WP_Error — whether that's because the circuit breaker is open
     * (chargeguard_circuit_open) or a single request failed/5xx'd below
     * the breaker's threshold. Both cases mean the same thing from a
     * security standpoint — "no authoritative decision is available for
     * this order" — and must never resolve to a silent, unconditional
     * approval.
     *
     * @param string $device_fp Untrusted, client-supplied — see the
     *                           trust-boundary warning at the top of this
     *                           file. Used only as a cheap first-line
     *                           heuristic here, exactly as elsewhere.
     * @param string $ip
     * @return array{decision:string, reason:string, local_block_type:?string}
     *         decision is 'approve' or 'block'.
     */
    private function resolve_api_unavailable_decision($device_fp, $ip) {
        $behavior = get_option(self::API_DOWN_BEHAVIOR_OPTION, 'local_checks');

        // 'allow_all' requires a SEPARATE, explicit acknowledgment flag.
        // Selecting it in the dropdown alone is not sufficient for a
        // setting this dangerous — this also protects against the option
        // being set directly via wp-cli/DB migration without ever going
        // through the settings-page checkbox flow. Falls back to the safe
        // default whenever the ack is missing.
        if ($behavior === 'allow_all' && get_option(self::API_DOWN_ALLOW_ALL_ACK_OPTION, '0') !== '1') {
            $behavior = 'local_checks';
        }

        if ($behavior === 'allow_all') {
            return ['decision' => 'approve', 'reason' => 'api_unavailable_allow_all_configured', 'local_block_type' => null];
        }

        if ($behavior === 'block_all') {
            return ['decision' => 'block', 'reason' => 'api_unavailable_fail_closed', 'local_block_type' => null];
        }

        // 'local_checks' — default / semi-open ------------------------------

        // 1. Local device blacklist — cheap, already-loaded option, same
        // data used by check_device_blacklist() / intercept_checkout_block().
        if (!empty($device_fp)) {
            $local_blacklist = get_option($this->blacklist_option, []);
            if (is_array($local_blacklist) && isset($local_blacklist[$device_fp]) && $local_blacklist[$device_fp] > time()) {
                return ['decision' => 'block', 'reason' => 'api_unavailable_local_blacklist', 'local_block_type' => 'blacklist'];
            }
        }

        // 2. Hard per-IP rate limit. This counter is ONLY ever incremented
        // from this method — i.e. only while the API is actually
        // unreachable — so it specifically bounds how many unscored
        // orders a single IP can push through during an outage or an
        // attacker-forced breaker-open window, without adding any
        // throttling to normal, healthy-API traffic.
        if (!empty($ip)) {
            $limit  = (int) apply_filters('chargeguard_api_down_rate_limit', (int) get_option(self::API_DOWN_RATE_LIMIT_OPTION, self::API_DOWN_RATE_LIMIT_DEFAULT_MAX));
            $window = (int) apply_filters('chargeguard_api_down_rate_limit_window', self::API_DOWN_RATE_LIMIT_WINDOW);
            $key    = self::API_DOWN_RATE_LIMIT_TRANSIENT_PREFIX . md5($ip);
            $count  = (int) get_transient($key);
            $count++;
            set_transient($key, $count, $window);
            if ($count > $limit) {
                return ['decision' => 'block', 'reason' => 'api_unavailable_rate_limited', 'local_block_type' => 'velocity'];
            }
        }

        // Neither local check tripped. The order proceeds, but the caller
        // MUST still treat this as a degraded/unscored order — see
        // notify_admin_api_unavailable() — so the merchant is never left
        // unaware their store is running with reduced protection.
        return ['decision' => 'approve', 'reason' => 'api_unavailable_local_checks_passed', 'local_block_type' => null];
    }

    /**
     * Reports a block produced by resolve_api_unavailable_decision() to
     * the backend's BlockedAttempt/dashboard reporting endpoint, so it
     * counts toward attack alerts and reports exactly like a normal
     * blacklist/velocity block. Fire-and-forget — see send_blocked_attempt().
     *
     * @param string $fingerprint
     * @param string $ip
     * @param string $type 'blacklist' or 'velocity' — matches
     *                      resolve_api_unavailable_decision()'s
     *                      local_block_type, mapped onto the backend's
     *                      existing VALID_REASONS set (no new reason value
     *                      is introduced server-side).
     */
    private function report_api_down_block($fingerprint, $ip, $type) {
        if (!$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }
        if (!method_exists($this->api_client, 'send_blocked_attempt')) {
            return;
        }
        $reason = ($type === 'blacklist') ? 'blacklist' : 'velocity';
        $this->api_client->send_blocked_attempt([
            'reason'            => $reason,
            'ipHash'            => $ip !== '' ? hash('sha256', $ip) : null,
            'deviceFingerprint' => $fingerprint,
        ]);
    }

    /**
     * Records that a fallback decision (block or degraded-approve) was
     * applied because the API was unreachable, and throttles a
     * merchant-visible admin notice about it. Mirrors the existing
     * notify_admin_quota_exceeded() pattern — one option is the source of
     * truth, read by maybe_show_api_down_notice() below, self-clearing
     * after an hour of no further occurrences.
     *
     * @param string $reason One of resolve_api_unavailable_decision()'s reason strings.
     */
    private function notify_admin_api_unavailable($reason) {
        $status = get_option(self::API_DOWN_STATUS_OPTION, []);
        if (!is_array($status)) {
            $status = [];
        }
        $window_start = isset($status['window_start']) ? (int) $status['window_start'] : 0;
        $now = time();
        if (!$window_start || ($now - $window_start) > HOUR_IN_SECONDS) {
            $status = ['window_start' => $now, 'count' => 0];
        }
        $status['count']       = (isset($status['count']) ? (int) $status['count'] : 0) + 1;
        $status['last_reason'] = $reason;
        $status['last_at']     = $now;
        update_option(self::API_DOWN_STATUS_OPTION, $status, false);

        error_log('ChargeGuard: evaluate_risk unavailable — applied fallback decision (' . $reason . ').');
    }

    /**
     * Admin-facing banner shown while (or shortly after) the store has
     * been applying the API-unavailable fallback behavior, so the
     * merchant always knows when and how their configured fallback mode
     * has actually been exercised — not just that the circuit breaker
     * exists in the abstract (see maybe_show_circuit_notice() in
     * class-api-client.php for the breaker-state-specific notice).
     */
    public function maybe_show_api_down_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        $status = get_option(self::API_DOWN_STATUS_OPTION, []);
        if (empty($status) || empty($status['last_at']) || (time() - (int) $status['last_at']) > HOUR_IN_SECONDS) {
            return;
        }
        $behavior = get_option(self::API_DOWN_BEHAVIOR_OPTION, 'local_checks');
        $mode_label = $behavior === 'block_all'
            ? __('blocking all orders (fail-closed)', 'chargeguard-woocommerce')
            : ($behavior === 'allow_all'
                ? __('approving all orders unscored (fail-open — not recommended)', 'chargeguard-woocommerce')
                : __('using local fallback checks (device blacklist + per-IP rate limit)', 'chargeguard-woocommerce'));
        ?>
        <div class="notice notice-warning">
            <p>
                <strong>ChargeGuard:</strong>
                <?php
                printf(
                    esc_html__('The fraud-scoring API has been unreachable %1$d time(s) in the last hour. Your store is currently %2$s. Configure this under ChargeGuard → Firewall Settings.', 'chargeguard-woocommerce'),
                    (int) ($status['count'] ?? 0),
                    esc_html($mode_label)
                );
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * Detects quota exhaustion on the order.created webhook path. Unlike
     * intercept_checkout()/intercept_checkout_block(), this path has no
     * synchronous PHP hook — WooCommerce core is the HTTP client for
     * webhook delivery, not this plugin (see class docblock). Hooked to
     * WooCommerce core's woocommerce_webhook_delivery, which fires after
     * EVERY webhook delivery attempt for EVERY webhook registered on the
     * site, so this must filter to ChargeGuard's own webhook first.
     *
     * Deliberately calls the existing notify_admin_quota_exceeded()
     * rather than duplicating its option-writing logic, so both paths
     * flag the identical merchant-facing state under the identical
     * option (chargeguard_quota_exceeded_status), read by the single
     * existing maybe_show_quota_exceeded_notice() notice with its
     * existing 24h self-clear — no new notice, message, or option needed.
     *
     * @param array          $http_args  wp_remote_post() args WooCommerce sent.
     * @param array|WP_Error $response   wp_remote_post()-style response, or
     *                                   WP_Error if the HTTP request itself
     *                                   failed (nothing to parse in that case).
     * @param float          $duration   Delivery duration in seconds.
     * @param mixed          $arg        The resource ID the webhook fired for.
     * @param int            $webhook_id The WC_Webhook's post ID.
     */
    public function maybe_flag_webhook_quota_exceeded($http_args, $response, $duration, $arg, $webhook_id) {
        $chargeguard_webhook_id = (int) get_option('chargeguard_webhook_id');
        if (!$chargeguard_webhook_id || (int) $webhook_id !== $chargeguard_webhook_id) {
            return; // Some other webhook the merchant configured — not ours.
        }

        if (is_wp_error($response)) {
            return; // Network-level delivery failure — no response body to inspect.
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($body)) {
            return;
        }

        // Back-compat: older backend versions send 'blocked_reason' for a
        // quota-exhausted evaluation; current versions send
        // 'limitedScoring: true' instead, with no blocked_reason field.
        if (!empty($body['blocked_reason']) && ($body['blocked_reason'] === 'quota_exceeded' || $body['blocked_reason'] === 'pro_quota_exceeded')) {
            $this->notify_admin_quota_exceeded($body['blocked_reason']);
        } elseif (!empty($body['limitedScoring'])) {
            $this->notify_admin_quota_exceeded('limited_scoring');
        }
    }

    /**
     * Admin-facing banner shown while the store is blocking checkouts
     * because of an exhausted plan quota, not an actual fraud decision.
     * Self-clears after 24h so a merchant who has since upgraded (or
     * whose quota has reset) doesn't see a permanently stuck warning.
     */
    public function maybe_show_quota_exceeded_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        $status = get_option('chargeguard_quota_exceeded_status', []);
        if (empty($status) || empty($status['flagged_at'])) {
            return;
        }
        if ((time() - (int) $status['flagged_at']) > DAY_IN_SECONDS) {
            return;
        }
        $reason = $status['reason'] ?? 'limited_scoring';

        if ($reason === 'pro_quota_exceeded') {
            $upgrade_hint = __('Your Pro plan\'s monthly protection limit (5,000 blocked attempts) has been reached — upgrade to Agency to restore full protection.', 'chargeguard-woocommerce');
        } elseif ($reason === 'quota_exceeded') {
            $upgrade_hint = __('Your Starter plan\'s monthly protection limit (500 blocked attempts) has been reached — upgrade to Pro to restore full protection.', 'chargeguard-woocommerce');
        } else {
            // 'limited_scoring' — current backend versions no longer report
            // which plan tier was exhausted in this signal, so the hint stays
            // generic rather than guessing a plan name.
            $upgrade_hint = __('Your ChargeGuard plan\'s monthly protection limit has been reached — upgrade your plan to restore full protection.', 'chargeguard-woocommerce');
        }
        ?>
        <div class="notice notice-warning">
            <p>
                <strong>ChargeGuard:</strong>
                <?php esc_html_e('Your fraud protection is currently running in a REDUCED mode. Device/IP blacklist checks, velocity limits, and card-testing (BIN sequence) detection are still active, but external IP, email, and BIN intelligence lookups are paused because your ChargeGuard plan limit was reached. Some fraud that only those deeper checks would catch may go through until you upgrade or your quota resets.', 'chargeguard-woocommerce'); ?>
                <?php echo esc_html($upgrade_hint); ?>
            </p>
        </div>
        <?php
    }

    /**
     * Report a local-blacklist block to the backend's dashboard/reporting
     * endpoint, so it counts toward BlockedAttempt stats, attack alerts,
     * and weekly/monthly reports exactly like blocks that go through
     * evaluate_risk(). Fire-and-forget — see send_blocked_attempt().
     *
     * @param string $fingerprint The device fingerprint that matched the
     *                            local blacklist.
     */
    private function report_blacklist_block($fingerprint) {
        if (!$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }
        if (!method_exists($this->api_client, 'send_blocked_attempt')) {
            return;
        }

        $ip = self::get_client_ip();

        $this->api_client->send_blocked_attempt([
            'reason'            => 'blacklist',
            'ipHash'            => $ip !== '' ? hash('sha256', $ip) : null,
            'deviceFingerprint' => $fingerprint,
        ]);
    }

    /**
     * Canonical read accessor for an order's device fingerprint.
     *
     * `_chargeguard_device_fp` is the single canonical meta key going
     * forward — written by intercept_checkout_block() (Blocks checkout)
     * and reconcile_pre_order_id() (classic checkout), so it has full
     * coverage of both checkout flows, unlike the now-removed
     * `_chargeguard_device_fingerprint` (see chargeguard-woocommerce.php),
     * which only ever populated for classic checkout since it relied on
     * woocommerce_checkout_create_order — a hook Blocks/Store API
     * checkout does not reliably fire.
     *
     * Falls back to the legacy key ONLY for orders created before this
     * unification shipped. Nothing writes the legacy key anymore — this
     * is a read-only, transitional compat shim, not an ongoing sync.
     *
     * @param int|WC_Order $order Order ID or object.
     * @return string Empty string if neither key is populated.
     */
    public static function get_order_device_fp($order) {
        $order = is_a($order, 'WC_Order') ? $order : wc_get_order($order);
        if (!$order) {
            return '';
        }
        $fp = $order->get_meta('_chargeguard_device_fp');
        if (!empty($fp)) {
            return $fp;
        }
        // Legacy fallback — pre-unification classic-checkout orders only.
        return (string) $order->get_meta('_chargeguard_device_fingerprint');
    }

    /**
     * Canonical read accessor for an order's server-signed device token.
     *
     * `_chargeguard_device_token` is written by intercept_checkout_block()
     * (Blocks checkout) and reconcile_pre_order_id() (classic checkout) —
     * same coverage pattern as get_order_device_fp() above. Unlike the
     * fingerprint, there is no legacy predecessor key to fall back to:
     * the device-token feature was introduced with this single key from
     * the start, so this is a plain accessor, not a compat shim.
     *
     * Used by chargeguard_add_fingerprint_to_webhook_payload() (see
     * chargeguard-woocommerce.php) to inject `device_token` into the
     * WooCommerce REST webhook payload, so /woocommerce-webhook on the
     * backend can verify it exactly as /evaluate and /enrich already do.
     *
     * @param int|WC_Order $order Order ID or object.
     * @return string Empty string if no token was ever issued/persisted
     *                for this order.
     */
    public static function get_order_device_token($order) {
        $order = is_a($order, 'WC_Order') ? $order : wc_get_order($order);
        if (!$order) {
            return '';
        }
        return (string) $order->get_meta('_chargeguard_device_token');
    }

    /**
     * إيقاف عرض الصفحة مع رسالة شفافة.
     */
    private function block_access($fingerprint = '') {
        if ($fingerprint !== '') {
            $this->report_blacklist_block($fingerprint);
        }

        throw new ChargeGuard_Blocked_Exception(
            esc_html__('Sorry, we are unable to process your request at this time. Please contact support.', 'chargeguard-woocommerce')
        );
    }

    // ─────────────────────────────────────────────
    // 3. Ajax: فحص البصمة من JavaScript
    // ─────────────────────────────────────────────

    /**
     * معالج Ajax لفحص بصمة الجهاز.
     */
    public function ajax_check_fingerprint() {
        check_ajax_referer('chargeguard_fw_nonce', 'nonce');

        // Per-IP rate limit — transient-based, matches the pattern used
        // elsewhere in the plugin (e.g. admin login throttling). Placed
        // before any blacklist lookup or outbound API call so a
        // rate-limited request does the minimum possible work and does
        // not leak blacklist membership.
        //
        // M3 fix: the previous version only enforced this limiter when
        // chargeguard_trust_proxy_headers was ON — backwards from what's
        // needed. When the setting is OFF (the default, and the config
        // of most stores), get_client_ip() returns REMOTE_ADDR: the
        // unspoofable, genuinely per-visitor TCP peer address. That is
        // precisely the case where a tight per-IP limiter is safe and
        // effective, yet it was the case being skipped, leaving this
        // public nopriv endpoint completely unthrottled by default —
        // enabling unlimited blacklist-membership probing and backend
        // check_device() cost amplification.
        //
        // The limiter now always runs. The only adjustment for the
        // "behind an untrusted-by-config proxy" case is a wider
        // threshold, not removing the limiter: when trust_proxy_headers
        // is on, get_client_ip() may return a header value shared by
        // many visitors behind the same CDN/load balancer, so the
        // threshold is raised to avoid collectively throttling
        // legitimate traffic, while still bounding total request volume.
        $rl_ip = self::get_client_ip();
        $rl_ip = $rl_ip !== '' ? $rl_ip : 'unknown';
        $rl_key = 'cg_fp_rl_' . md5($rl_ip);
        $rl_limit = get_option('chargeguard_trust_proxy_headers', 0) ? 100 : 10;
        $rl_count = get_transient($rl_key);
        if ($rl_count === false) {
            set_transient($rl_key, 1, 60);
        } elseif ($rl_count >= $rl_limit) {
            wp_send_json_error(['message' => 'rate_limited'], 429);
        } else {
            set_transient($rl_key, $rl_count + 1, 60);
        }

        // Same trust boundary as $_COOKIE['chargeguard_fp'] above: this
        // value is whatever the client's JavaScript posted, unverified.
        $fingerprint = isset($_POST['fingerprint'])
            ? sanitize_text_field(wp_unslash($_POST['fingerprint']))
            : '';

        $this->maybe_log_malformed_fingerprint($fingerprint);

        $blocked = false;

        // فحص محلي — مطابقة للمفتاح (بصمة الجهاز) مع التحقق من صلاحية الحظر،
        // بنفس نمط check_device_blacklist() أعلاه
        $blacklist = get_option($this->blacklist_option, []);
        if (is_array($blacklist) && isset($blacklist[$fingerprint]) && $blacklist[$fingerprint] > time()) {
            $blocked = true;
        }

        // فحص API
        if (!$blocked && $this->api_client && $this->api_client->get_api_key()) {
            $response = $this->api_client->check_device($fingerprint);
            if (!is_wp_error($response) && isset($response['blocked']) && $response['blocked']) {
                $blocked = true;
                $this->add_device_to_blacklist($fingerprint);
            }
        }

        wp_send_json_success(['blocked' => $blocked]);
    }
        // تحميل عميل API إن كان موجودًا
    /**
     * اعتراض عملية الدفع واستشارة ChargeGuard API.
     *
     * UX NOTE: The client-side pre-emptive "blocked" message (see
     * assets/js/chargeguard-firewall.js) only targets Classic checkout's
     * form.checkout selector and does not currently match anything on
     * Blocks checkout. This is intentional for this release — it is a
     * UX gap, not a security gap: the RouteException thrown below is
     * the actual enforcement point and fires regardless of which
     * checkout the customer is using. A Blocks-compatible pre-emptive
     * warning is tracked for a future release.
     */
    public function intercept_checkout_block($order, $request) {
        // Untrusted, client-forgeable value — see the trust-boundary
        // warning at the top of this file. The local blacklist check
        // just below is a cheap first-line heuristic only; evaluate_risk()
        // further down is the authoritative decision.
        $device_fp = isset($_COOKIE['chargeguard_fp']) ? sanitize_text_field(wp_unslash($_COOKIE['chargeguard_fp'])) : '';

        // فحص القائمة السوداء المحلية أولاً — يعمل بغض النظر عن توفر عميل
        // الـ API، بنفس نمط check_device_blacklist() المستخدم في classic
        // checkout، لضمان عدم فقدان هذه الحماية إذا كان مفتاح الـ API غير
        // مُعد. يتم الفحص قبل استدعاء evaluate_risk() لتفادي استهلاك طلب
        // شبكة غير ضروري ولضمان الحظر حتى لو تعذّر الوصول للـ backend لاحقًا.
        if (!empty($device_fp)) {
            $local_blacklist = get_option($this->blacklist_option, []);
            if (is_array($local_blacklist) && isset($local_blacklist[$device_fp]) && $local_blacklist[$device_fp] > time()) {
                $this->report_blacklist_block($device_fp);

                $message = __('Sorry, your order cannot be processed.', 'chargeguard-woocommerce');

                if (class_exists('\Automattic\WooCommerce\StoreApi\Exceptions\RouteException')) {
                    throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                        'chargeguard_order_blocked',
                        $message,
                        400
                    );
                }

                throw new \Exception($message);
            }
        }

        // Blocks checkout already has a real, persisted order at this point
        // (unlike classic checkout, which needs reconcile_pre_order_id()).
        // Persist the fingerprint now so post-payment webhook handlers can
        // resolve it later regardless of what evaluate_risk() below decides.
        if (!empty($device_fp) && $device_fp !== 'unknown') {
            $order->update_meta_data('_chargeguard_device_fp', $device_fp);
            $order->save_meta_data();
        }

        if (!$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }
        $ip = self::get_client_ip();
        $email = $order->get_billing_email();
        $amount = $order->get_total();
        $billing_country = $order->get_billing_country();
        $shipping_country = $order->get_shipping_country();

        // Blocks checkout has already created and persisted a real
        // WooCommerce order by the time this hook fires (WooCommerce's
        // Store API creates the draft order before calling checkout
        // extension hooks), so $order->get_id() is a real, permanent ID —
        // never a throwaway one. Using it directly means this evaluation
        // is correlatable with later dispute/feedback events with no
        // separate reconciliation step needed.
        // HttpOnly — never touched or overwritten by client JS, unlike
        // chargeguard_fp. Absent for un-upgraded installs or visitors who
        // loaded checkout before maybe_issue_device_token() could mint one
        // (e.g. first request in a session) — the backend treats a missing
        // token as 'unsigned', identical to today's behavior.
        $device_token = isset($_COOKIE['chargeguard_dt']) ? sanitize_text_field(wp_unslash($_COOKIE['chargeguard_dt'])) : '';

        // Persist the checkout-time device token onto the real order (Blocks
        // checkout already has a real, persisted order at this point) so
        // post-payment webhook handlers can thread it into /enrich the same
        // way /evaluate already receives it above.
        if (!empty($device_token)) {
            $order->update_meta_data('_chargeguard_device_token', $device_token);
            $order->save_meta_data();
        }

        $order_data = [
            'orderId' => (string) $order->get_id(),
            'email' => $email,
            'ipAddress' => $ip,
            'deviceFingerprint' => $device_fp,
            'deviceToken' => $device_token,
            'amount' => (float)$amount,
            'billingCountry' => $billing_country,
            'shippingCountry' => $shipping_country,
            'merchantId' => get_option('chargeguard_merchant_id', ''),
        ];

        $result = $this->api_client->evaluate_risk($order_data);

        if (is_wp_error($result)) {
            // Was previously: `return;` — an unconditional, silent
            // fail-open. This is the exploitable bypass: an attacker who
            // forces the circuit breaker open (or even a single failed
            // request) could walk through unscored. Both circuit-open and
            // single-request-failure cases arrive here identically and are
            // now routed through the merchant's configured fallback.
            $fallback = $this->resolve_api_unavailable_decision($device_fp, $ip);
            $this->notify_admin_api_unavailable($fallback['reason']);

            if ($fallback['decision'] === 'block') {
                if ($fallback['local_block_type']) {
                    $this->report_api_down_block($device_fp, $ip, $fallback['local_block_type']);
                }

                $message = __('Sorry, your order cannot be processed at this time. Please try again shortly.', 'chargeguard-woocommerce');

                if (class_exists('\Automattic\WooCommerce\StoreApi\Exceptions\RouteException')) {
                    throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                        'chargeguard_order_blocked_api_unavailable',
                        $message,
                        400
                    );
                }
                throw new \Exception($message);
            }

            // Fallback resolved to 'approve' (local_checks mode, cleared
            // both local checks; or allow_all, explicitly acknowledged).
            // The order proceeds, already flagged above as degraded/unscored.
            return;
        }

        $decision = isset($result['decision']) ? $result['decision'] : '';
        $blocked_reason = isset($result['blocked_reason']) ? $result['blocked_reason'] : '';
        $limited_scoring = !empty($result['limitedScoring']);

        // Quota-exhausted orders now come back as decision: 'approve' — the
        // order is allowed through, and cheap detectors (blacklist,
        // velocity, BIN-sequence) still ran; only external IP/email/BIN
        // intelligence was skipped. We never throw here; we only flag the
        // admin that protection is currently degraded for this store.
        //
        // Back-compat: older backend versions send 'blocked_reason' for
        // this state; current versions send 'limitedScoring: true' with
        // no blocked_reason at all. Check both.
        if ($blocked_reason === 'quota_exceeded' || $blocked_reason === 'pro_quota_exceeded') {
            $this->notify_admin_quota_exceeded($blocked_reason);
        } elseif ($limited_scoring) {
            $this->notify_admin_quota_exceeded('limited_scoring');
        }

        if ($decision === 'block') {
            if (!empty($device_fp) && $device_fp !== 'unknown') {
                do_action('chargeguard_mark_device_fraud', $device_fp, 'chargeguard_api_block');
            }

            $message = __('Sorry, your order cannot be processed.', 'chargeguard-woocommerce');

            if (class_exists('\Automattic\WooCommerce\StoreApi\Exceptions\RouteException')) {
                throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
                    'chargeguard_order_blocked',
                    $message,
                    400
                );
            }

            // Fallback for WooCommerce installs without the Store API exception
            // class available (should not occur in practice, since this hook
            // itself is a Store API hook — kept only as a defensive guard).
            throw new \Exception($message);
        }
    }

    public function intercept_checkout() {
        // لا تفعل شيئًا إذا لم يكن هناك عميل API أو مفتاح
        if (!$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }

        // تجهيز البيانات
        $ip = self::get_client_ip();
        $email = isset($_POST['billing_email']) ? sanitize_email(wp_unslash($_POST['billing_email'])) : '';
        // Untrusted, client-forgeable value — see the trust-boundary
        // warning at the top of this file; evaluate_risk() below, not
        // this value alone, is what actually decides the outcome.
        $device_fp = isset($_COOKIE['chargeguard_fp']) ? sanitize_text_field(wp_unslash($_COOKIE['chargeguard_fp'])) : '';
        $amount = WC()->cart ? WC()->cart->total : 0;
        $billing_country = isset($_POST['billing_country']) ? sanitize_text_field(wp_unslash($_POST['billing_country'])) : '';
        $shipping_country = isset($_POST['shipping_country']) ? sanitize_text_field(wp_unslash($_POST['shipping_country'])) : '';

        // Classic checkout has no order object yet at this hook — WooCommerce
        // doesn't create one until woocommerce_checkout_create_order, later
        // in the same request. Track this ID on the instance so
        // reconcile_pre_order_id() can send it to the backend once the real
        // order exists.
        $this->pre_order_id  = 'pre_' . uniqid('', true);
        $this->pre_device_fp = $device_fp;

        $device_token = isset($_COOKIE['chargeguard_dt']) ? sanitize_text_field(wp_unslash($_COOKIE['chargeguard_dt'])) : '';
        $this->pre_device_token = $device_token;

        $order_data = [
            'orderId'         => $this->pre_order_id,
            'email'           => $email,
            'ipAddress'       => $ip,
            'deviceFingerprint' => $device_fp,
            'deviceToken'     => $device_token,
            'amount'          => (float)$amount,
            'billingCountry'  => $billing_country,
            'shippingCountry' => $shipping_country,
            'merchantId'      => get_option('chargeguard_merchant_id', ''),
        ];

        $result = $this->api_client->evaluate_risk($order_data);

        // Was previously: log and unconditionally let the order pass
        // ("لأسباب أمان" / "for safety reasons") — that was the
        // exploitable bypass. Now routed through the same fallback logic
        // as Blocks checkout (see intercept_checkout_block()), so both
        // checkout flows behave identically when the API is unreachable.
        if (is_wp_error($result)) {
            error_log('ChargeGuard API error: ' . $result->get_error_code());

            $fallback = $this->resolve_api_unavailable_decision($device_fp, $ip);
            $this->notify_admin_api_unavailable($fallback['reason']);

            if ($fallback['decision'] === 'block') {
                if ($fallback['local_block_type']) {
                    $this->report_api_down_block($device_fp, $ip, $fallback['local_block_type']);
                }
                $message = __('Sorry, your order cannot be processed at this time. Please try again shortly.', 'chargeguard-woocommerce');
                wc_add_notice($message, 'error');
            }

            // Whether blocked (wc_add_notice('error') above halts
            // woocommerce_checkout_process the same way the existing
            // decision === 'block' branch below does) or approved
            // (local_checks/allow_all resolved to approve), there is
            // nothing further to score for this request.
            return;
        }

        // لا نُسجّل أي بيانات شخصية (بريد، IP، بصمة الجهاز) — فقط القرار،
        // اتساقًا مع مبدأ تقليل البيانات (data minimization).
        error_log('ChargeGuard checkout evaluated — pre_order_id: ' . $this->pre_order_id . ', decision: ' . (isset($result['decision']) ? $result['decision'] : 'unknown'));

        $decision = isset($result['decision']) ? $result['decision'] : '';
        $blocked_reason = isset($result['blocked_reason']) ? $result['blocked_reason'] : '';
        $limited_scoring = !empty($result['limitedScoring']);

        // Quota-exhausted orders come back as decision: 'approve' — the
        // customer's checkout proceeds, and cheap detectors (blacklist,
        // velocity, BIN-sequence) still ran; only external IP/email/BIN
        // intelligence was skipped. We still flag the merchant that
        // protection is degraded, but we do not add a customer-facing
        // error notice for this case.
        //
        // Back-compat: older backend versions send 'blocked_reason' for
        // this state; current versions send 'limitedScoring: true' with
        // no blocked_reason at all. Check both.
        if ($blocked_reason === 'quota_exceeded' || $blocked_reason === 'pro_quota_exceeded') {
            $this->notify_admin_quota_exceeded($blocked_reason);
        } elseif ($limited_scoring) {
            $this->notify_admin_quota_exceeded('limited_scoring');
        }

        // حظر الطلب إذا كان القرار "block" لأسباب فعلية غير الكوتا
        if ($decision === 'block') {
            // Activate the local firewall: a confirmed block decision from
            // the authoritative /risk/evaluate call is exactly the signal
            // that should populate the local device blacklist, so this
            // device is stopped at the PHP level on its next attempt
            // without needing another API round-trip.
            if (!empty($device_fp) && $device_fp !== 'unknown') {
                do_action('chargeguard_mark_device_fraud', $device_fp, 'chargeguard_api_block');
            }

            $message = __('Sorry, your order cannot be processed.', 'chargeguard-woocommerce');
            wc_add_notice($message, 'error');
        }
    }

    /**
     * يربط تقييم ما قبل الطلب (classic checkout) بمعرف الطلب الحقيقي بمجرد
     * إنشائه، حتى تتمكن حلقة الـ feedback loop في الـ backend من مطابقة
     * أي نزاع أو تغذية راجعة لاحقة بالتقييم الأصلي.
     *
     * Fires on woocommerce_checkout_order_created — the same request as
     * intercept_checkout(), so $this->pre_order_id (set there) is still
     * available. No-ops safely for Blocks checkout (which never sets
     * $this->pre_order_id, since intercept_checkout_block() now uses the
     * real order ID directly) and for guest/failed evaluations where no
     * pre-order ID was generated.
     *
     * @param WC_Order $order الطلب الذي تم إنشاؤه للتو.
     */
    public function reconcile_pre_order_id($order) {
        if (!$this->pre_order_id || !$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }

        // Kept as order meta too, independent of the backend call, so
        // support/debugging can trace a specific order back to its
        // original pre-order evaluation ID even if the reconciliation
        // call itself failed or the backend is unreachable.
        $order->update_meta_data('_chargeguard_pre_order_id', $this->pre_order_id);

        // Persist the checkout-time device fingerprint onto the real order
        // so post-payment webhook handlers (Stripe/PayPal), which never see
        // the fingerprint cookie themselves, can still resolve which device
        // to blacklist on a later block or dispute decision.
        if (!empty($this->pre_device_fp) && $this->pre_device_fp !== 'unknown') {
            $order->update_meta_data('_chargeguard_device_fp', $this->pre_device_fp);
        }

        // Same rationale as _chargeguard_device_fp above: post-payment
        // webhook handlers (Stripe/PayPal) never see the chargeguard_dt
        // cookie themselves, so it has to be persisted here to be usable
        // by /enrich later.
        if (!empty($this->pre_device_token)) {
            $order->update_meta_data('_chargeguard_device_token', $this->pre_device_token);
        }

        $order->save_meta_data();

        $this->api_client->reconcile_order($this->pre_order_id, $order->get_id());

        // Reset for safety — WooCommerce reuses controller/singleton
        // instances across requests in some server configs (e.g. certain
        // persistent PHP setups), so this must not leak into an unrelated
        // later request.
        $this->pre_order_id     = null;
        $this->pre_device_fp    = null;
        $this->pre_device_token = null;
    }
}