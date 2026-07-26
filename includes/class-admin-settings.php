<?php

defined('ABSPATH') || exit;

/**
 * True if $host is a literal private/reserved IP, or a hostname that
 * resolves to one — guards ajax_webhook_save() against SSRF, including
 * DNS-rebinding style attacks where the hostname itself looks public.
 */
/**
 * @param string      $host
 * @param string|null &$resolved_ip Output parameter (by reference, optional).
 *                                  On return, set to the IP address this
 *                                  host was validated against (whether the
 *                                  host was itself a literal IP, or was
 *                                  resolved via gethostbyname()), or ''
 *                                  if resolution failed. Callers that
 *                                  need to forward the validated IP to
 *                                  another system (see ajax_webhook_save())
 *                                  should capture this rather than
 *                                  re-resolving the host a second time —
 *                                  a second lookup could itself return a
 *                                  different address than the one just
 *                                  validated here, reopening a small
 *                                  version of the same TOCTOU gap this
 *                                  value exists to help close downstream.
 */
function chargeguard_host_is_private_or_reserved($host, &$resolved_ip = null) {
    $host = trim($host, '[]'); // strip IPv6 literal brackets, if present
    $resolved_ip = '';

    // IPv4-mapped IPv6 unwrap (::ffff:a.b.c.d, RFC 4291 §2.5.5.2). PHP's
    // FILTER_FLAG_NO_PRIV_RANGE / FILTER_FLAG_NO_RES_RANGE checks below
    // are applied against $host as an IPv6-format string when it
    // contains colons, and whether that correctly recognizes an
    // embedded IPv4 private/reserved address (e.g. ::ffff:169.254.169.254
    // for the cloud metadata endpoint) is inconsistent across PHP
    // versions/builds — this is a known SSRF bypass vector for exactly
    // this class of target. An IPv4-mapped IPv6 address IS the same
    // network address as its IPv4 form (not merely related to it), so
    // unwrapping it here and letting every check below operate on the
    // plain IPv4 dotted-quad — which PHP's range flags handle reliably
    // — closes the ambiguity rather than trying to special-case around
    // it downstream.
    $packed = @inet_pton($host);
    if ($packed !== false && strlen($packed) === 16 && substr($packed, 0, 10) === str_repeat("\x00", 10) && substr($packed, 10, 2) === "\xff\xff") {
        $ipv4_binary = substr($packed, 12, 4);
        $unwrapped   = inet_ntop($ipv4_binary);
        if ($unwrapped !== false) {
            $host = $unwrapped;
        }
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ip = $host;
    } else {
        if (strtolower($host) === 'localhost') {
            return true;
        }
        // PERFORMANCE NOTE (Low severity, accepted for v1.0):
        // gethostbyname() is a blocking, synchronous call with no built-in
        // timeout. A slow, unresponsive, or malicious DNS server for this
        // hostname can tie up this PHP-FPM worker for an unbounded duration
        // (up to max_execution_time). Accepted as-is because:
        //   - This runs only inside ajax_webhook_save(), which is admin-only
        //     and capability-gated (manage_woocommerce) — not reachable by
        //     storefront visitors and not on the checkout hot path.
        //   - It fires rarely (a merchant saving/changing a webhook URL),
        //     not on every request.
        //   - PHP has no clean, universal async DNS primitive: pcntl_alarm()
        //     is frequently unavailable on shared/managed FPM hosts, and
        //     shelling out to an external resolver with a timeout trades this
        //     narrow risk for a new exec()/argument-escaping dependency that
        //     is itself often disabled on hardened hosts. Neither is a net
        //     improvement over the status quo.
        // If this needs tightening in a future hardening pass, the correct
        // fix is architectural, not a timeout hack: move webhook-URL
        // validation into a WP-Cron job or background queue so any DNS
        // slowdown is isolated from the web request entirely, rather than
        // trying to force a timeout onto PHP's native synchronous resolver.
        $resolved = gethostbyname($host);
        // gethostbyname() returns the input unchanged on failure to resolve.
        if ($resolved === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
            return true; // couldn't resolve — fail closed
        }
        $ip = $resolved;

        // A hostname's A record passing the check below says nothing
        // about its AAAA record. An attacker controlling DNS for the
        // host can publish a public A record (which will pass) next to
        // a private/link-local AAAA record; if the backend's HTTP
        // client later prefers or falls back to IPv6 when delivering
        // the webhook, it connects to an address this function never
        // inspected. Every resolvable address family must be checked,
        // not just whichever one gethostbyname() happens to return.
        if (function_exists('dns_get_record')) {
            $aaaa_records = @dns_get_record($host, DNS_AAAA);
            if (is_array($aaaa_records)) {
                foreach ($aaaa_records as $record) {
                    if (empty($record['ipv6'])) {
                        continue;
                    }
                    $aaaa_is_private = filter_var(
                        $record['ipv6'],
                        FILTER_VALIDATE_IP,
                        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                    ) === false;
                    if ($aaaa_is_private) {
                        return true; // private/reserved AAAA record — reject regardless of the A record
                    }
                }
            }
        } else {
            static $ipv6_ssrf_check_warning_logged = false;
            if (!$ipv6_ssrf_check_warning_logged) {
                error_log('[ChargeGuard] dns_get_record() is unavailable on this host — webhook URL validation cannot inspect AAAA (IPv6) records for SSRF and is falling back to IPv4-only (gethostbyname()) validation.');
                $ipv6_ssrf_check_warning_logged = true;
            }
        }
    }

    $resolved_ip = $ip;

    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;
}

/**
 * ChargeGuard - Secret Storage Encryption
 *
 * Brings third-party secrets (Stripe/PayPal) up to the same at-rest
 * protection standard already applied to chargeguard_api_key.
 *
 * AES-256-GCM (authenticated encryption) with a key derived from
 * WordPress's own wp_salt('auth') — no new secret material needs to be
 * generated, stored, or rotated by the plugin itself. wp_salt() already
 * falls back to a DB-stored value when AUTH_KEY/AUTH_SALT constants are
 * undefined, so this works on every WP install with zero configuration.
 */
class ChargeGuard_Secret_Crypto {

    const PREFIX = 'cgenc1:'; // format + version marker

    /**
     * Derive the AES-256-GCM key.
     *
     * If CHARGEGUARD_ENCRYPTION_KEY is defined (wp-config.php or an OS
     * environment variable read into a constant), it is used exclusively
     * — this keeps key material outside the database entirely, even on
     * hosts that never set AUTH_KEY/AUTH_SALT.
     *
     * Otherwise falls back to wp_salt('auth'), matching the original
     * behavior. This is safe when AUTH_KEY/AUTH_SALT are hardcoded in
     * wp-config.php, but on installs where WordPress generated and
     * stored those salts in wp_options itself, the key material and the
     * ciphertext live in the same database — see
     * ChargeGuard_Admin_Settings::maybe_show_key_derivation_notice().
     */
    private static function get_key() {
        if (defined('CHARGEGUARD_ENCRYPTION_KEY') && CHARGEGUARD_ENCRYPTION_KEY) {
            return hash('sha256', CHARGEGUARD_ENCRYPTION_KEY, true);
        }
        return self::get_legacy_key();
    }

    /**
     * The pre-CHARGEGUARD_ENCRYPTION_KEY derivation, kept as its own
     * method so decrypt() can fall back to it once, transparently, when
     * migrating existing ciphertext to a newly-defined
     * CHARGEGUARD_ENCRYPTION_KEY (see decrypt()).
     */
    private static function get_legacy_key() {
        return hash('sha256', wp_salt('auth'), true); // 32 raw bytes
    }

    public static function encrypt($plaintext) {
        if (!is_string($plaintext) || $plaintext === '') {
            return $plaintext;
        }
        $key = self::get_key();
        $iv  = random_bytes(12); // GCM standard nonce size
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ciphertext === false) {
            // Fail loud, never silently fall back to storing plaintext
            // mislabeled as encrypted.
            return false;
        }
        return self::PREFIX . base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * @param string $stored
     * @param bool   $migrated Set true (by reference) if this value only
     *                         decrypted successfully under the legacy
     *                         wp_salt('auth')-derived key, meaning the
     *                         caller should re-encrypt it under the
     *                         current key (see chargeguard_get_secret_option()).
     */
    public static function decrypt($stored, &$migrated = false) {
        $migrated = false;
        if (!is_string($stored) || $stored === '') {
            return $stored;
        }
        if (strpos($stored, self::PREFIX) !== 0) {
            return $stored; // legacy plaintext, not our format
        }
        $raw = base64_decode(substr($stored, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) < 12 + 16) {
            return false;
        }
        $iv         = substr($raw, 0, 12);
        $tag        = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', self::get_key(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($plaintext !== false) {
            return $plaintext;
        }

        // Current key failed. If CHARGEGUARD_ENCRYPTION_KEY is now
        // configured, this ciphertext may predate that change and still
        // be under the old wp_salt('auth')-derived key — try that once
        // as a migration path rather than treating it as corrupt.
        if (defined('CHARGEGUARD_ENCRYPTION_KEY') && CHARGEGUARD_ENCRYPTION_KEY) {
            $legacy_plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', self::get_legacy_key(), OPENSSL_RAW_DATA, $iv, $tag);
            if ($legacy_plaintext !== false) {
                $migrated = true;
                return $legacy_plaintext;
            }
        }

        return false;
        // returns false on authentication failure under every key we
        // tried (tampered/corrupt data, or a changed wp_salt with no
        // CHARGEGUARD_ENCRYPTION_KEY fallback available) — never returns
        // garbage plaintext.
    }

    public static function is_encrypted($value) {
        return is_string($value) && strpos($value, self::PREFIX) === 0;
    }
}

/**
 * Transparent get/update wrappers for third-party secret options.
 * Call sites use these exactly like get_option()/update_option() —
 * encryption/decryption is invisible to the rest of the codebase.
 *
 * Self-healing migration: a legacy plaintext value is still returned
 * correctly on read, and is opportunistically re-saved encrypted at
 * that point — no separate upgrade routine needed.
 */
function chargeguard_get_secret_option($name, $default = '') {
    static $cache = [];
    if (array_key_exists($name, $cache)) {
        return $cache[$name];
    }

    $stored = get_option($name, $default);

    if (!is_string($stored) || $stored === '') {
        $cache[$name] = $stored;
        return $stored;
    }

    if (ChargeGuard_Secret_Crypto::is_encrypted($stored)) {
        $migrated  = false;
        $plaintext = ChargeGuard_Secret_Crypto::decrypt($stored, $migrated);
        if ($plaintext === false) {
            chargeguard_flag_secret_decrypt_failure($name);
            $cache[$name] = '';
            return '';
        }
        chargeguard_clear_secret_decrypt_failure($name);
        if ($migrated) {
            // Was still encrypted under the legacy wp_salt('auth')-derived
            // key; re-save under the current (CHARGEGUARD_ENCRYPTION_KEY)
            // key now that we've proven we can read it.
            chargeguard_update_secret_option($name, $plaintext);
            error_log('[ChargeGuard] Migrated option ' . $name . ' from wp_salt-derived key to CHARGEGUARD_ENCRYPTION_KEY.');
        }
        $cache[$name] = $plaintext;
        return $plaintext;
    }

    // Legacy plaintext — self-heal in place; still return plaintext now.
    chargeguard_update_secret_option($name, $stored);
    $cache[$name] = $stored;
    return $stored;
}

/**
 * Record a persistent, merchant-visible flag when a secret fails to
 * decrypt on read (see chargeguard_get_secret_option()). Mirrors the
 * existing chargeguard_signing_self_test option pattern: a single
 * source-of-truth option that admin_notices checks, cleared the moment
 * the same option decrypts successfully again (see
 * chargeguard_clear_secret_decrypt_failure()). update_option() is used
 * rather than a transient for this flag — exactly like
 * chargeguard_signing_self_test — because a transient would silently
 * expire and make a still-broken config look "fixed" to the merchant
 * purely because time passed, which is the wrong failure mode for a
 * security notice.
 *
 * A short-lived transient is used separately, only to throttle the
 * error_log write below, so a broken secret being read many times per
 * minute (e.g. by risk-evaluation code on every order) doesn't flood
 * the log.
 */
function chargeguard_flag_secret_decrypt_failure($name) {
    // Gate the update_option() write behind the same hourly throttle
    // that already protects the error_log() call below. Without this,
    // a persistent decrypt failure (e.g. post-migration salt change with
    // no CHARGEGUARD_ENCRYPTION_KEY defined) causes a full get_option()/
    // update_option() round trip on wp_options for every single read
    // attempt — every checkout, admin page load, and AJAX request that
    // touches the affected secret — even though the merchant-visible
    // notice only needs the option written once per failure window.
    // Checking the transient first, before any DB write, keeps both
    // throttles synchronized on the exact same one-per-hour cadence.
    $log_throttle_key = 'chargeguard_secret_decrypt_logged_' . $name;
    if (get_transient($log_throttle_key)) {
        return;
    }

    $failures = get_option('chargeguard_secret_decrypt_failures', []);
    if (!is_array($failures)) {
        $failures = [];
    }
    $failures[$name] = time();
    update_option('chargeguard_secret_decrypt_failures', $failures);

    error_log('[ChargeGuard] Failed to decrypt option ' . $name . ' — data may be corrupt or wp_salt() has changed.');
    set_transient($log_throttle_key, 1, HOUR_IN_SECONDS);
}

/**
 * Clear a previously-flagged decrypt failure once the same option is
 * read successfully again (e.g. after the merchant re-enters the
 * credential and it round-trips through the current wp_salt()).
 */
function chargeguard_clear_secret_decrypt_failure($name) {
    $failures = get_option('chargeguard_secret_decrypt_failures', []);
    if (!is_array($failures) || !isset($failures[$name])) {
        return;
    }
    unset($failures[$name]);
    update_option('chargeguard_secret_decrypt_failures', $failures);
}

function chargeguard_update_secret_option($name, $value) {
    if (!is_string($value) || $value === '') {
        return update_option($name, $value);
    }
    $encrypted = ChargeGuard_Secret_Crypto::encrypt($value);
    if ($encrypted === false) {
        error_log('[ChargeGuard] Failed to encrypt option ' . $name . ' — refusing to store plaintext.');
        return false;
    }
    return update_option($name, $encrypted);
}

class ChargeGuard_Admin_Settings {

    /**
     * TTL for the chargeguard_merchant_plan_cache transient (see
     * settings_page() and merchant_is_pro_or_above_cached()). Both call
     * sites read/write the SAME transient key and must use the SAME TTL —
     * defined once here rather than as two independent literals, so they
     * cannot silently drift out of sync (the class of bug already flagged
     * elsewhere in this codebase as CWE-1059).
     *
     * 60 seconds (down from a prior 5 minutes) bounds how long the WP
     * admin UI can show a stale plan tier after a backend-side upgrade/
     * downgrade. This is a UI-freshness knob only — every actual
     * entitlement decision (PayPal alert delivery, quota enforcement,
     * plan-gated API responses) is re-checked against the backend at the
     * point of use and is never affected by this cache.
     */
    const PLAN_CACHE_TTL = 60; // seconds

    public function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_notices', [$this, 'maybe_show_signing_self_test_notice']);
        add_action('admin_notices', [$this, 'maybe_show_secret_decrypt_notice']);
        add_action('admin_notices', [$this, 'maybe_show_key_derivation_notice']);
        add_action('admin_notices', [$this, 'maybe_show_turnstile_notice']);
        add_action('wp_ajax_chargeguard_connect', [$this, 'ajax_connect']);
        add_action('wp_ajax_chargeguard_connect_poll', [$this, 'ajax_connect_poll']);
        add_action('wp_ajax_chargeguard_disconnect', [$this, 'ajax_disconnect']);
        add_action('wp_ajax_chargeguard_verify_key',  [$this, 'ajax_verify_key']);
        add_action('wp_ajax_chargeguard_whitelist_get',    [$this, 'ajax_whitelist_get']);
        add_action('wp_ajax_chargeguard_whitelist_add',    [$this, 'ajax_whitelist_add']);
        add_action('wp_ajax_chargeguard_whitelist_delete', [$this, 'ajax_whitelist_delete']);
        add_action('wp_ajax_chargeguard_blacklist_get',    [$this, 'ajax_blacklist_get']);
        add_action('wp_ajax_chargeguard_blacklist_add',    [$this, 'ajax_blacklist_add']);
        add_action('wp_ajax_chargeguard_blacklist_delete', [$this, 'ajax_blacklist_delete']);
        add_action('wp_ajax_chargeguard_webhook_save',     [$this, 'ajax_webhook_save']);
        add_action('wp_ajax_chargeguard_webhook_test',     [$this, 'ajax_webhook_test']);
        add_action('wp_ajax_chargeguard_webhook_status',        [$this, 'ajax_webhook_status']);
        add_action('wp_ajax_chargeguard_geo_overrides_get',     [$this, 'ajax_geo_overrides_get']);
        add_action('wp_ajax_chargeguard_geo_override_save',     [$this, 'ajax_geo_override_save']);
        add_action('wp_ajax_chargeguard_paypal_save',           [$this, 'ajax_paypal_save']);
        add_action('wp_ajax_chargeguard_paypal_test',           [$this, 'ajax_paypal_test']);
        add_action('wp_ajax_chargeguard_stripe_save',           [$this, 'ajax_stripe_save']);
        add_action('wp_ajax_chargeguard_stripe_test',           [$this, 'ajax_stripe_test']);
        add_action('wp_ajax_chargeguard_stores_get',            [$this, 'ajax_stores_get']);
        add_action('wp_ajax_chargeguard_store_add',             [$this, 'ajax_store_add']);
        add_action('wp_ajax_chargeguard_store_rename',          [$this, 'ajax_store_rename']);
        add_action('wp_ajax_chargeguard_store_deactivate',      [$this, 'ajax_store_deactivate']);
        add_action('wp_ajax_chargeguard_store_reactivate',      [$this, 'ajax_store_reactivate']);
        add_action('wp_ajax_chargeguard_check_for_updates',     [$this, 'ajax_check_for_updates']);

        // Align the Settings API's save-time capability check with the
        // capability actually required to reach this settings page
        // (manage_woocommerce, set on add_submenu_page() in
        // add_admin_menu()). Without this, register_setting() calls in
        // register_settings() below default to requiring manage_options
        // when the form POSTs to options.php — a capability Shop
        // Managers (manage_woocommerce but not manage_options) do not
        // have — even though the page itself already let them in. See
        // the option_page_capability_{$option_page} filter in
        // WordPress core's wp-admin/options.php.
        add_filter('option_page_capability_chargeguard_firewall_settings', fn() => 'manage_woocommerce');
        add_filter('option_page_capability_chargeguard_autoblock_settings', fn() => 'manage_woocommerce');
        add_filter('option_page_capability_chargeguard_apidown_settings', fn() => 'manage_woocommerce');
    }

    public function add_admin_menu() {
        $this->settings_page_hook = add_submenu_page(
            'woocommerce',
            'ChargeGuard',
            'ChargeGuard',
            'manage_woocommerce',
            'chargeguard-settings',
            [$this, 'settings_page']
        );
    }

    /**
     * The hook suffix WordPress assigns to this settings page, captured
     * from add_submenu_page()'s own return value rather than guessed —
     * since this page is a WooCommerce submenu, its real hook suffix is
     * `woocommerce_page_chargeguard-settings`, not the more commonly
     * assumed `toplevel_page_...` pattern used by top-level menu pages.
     * Using the actual returned value avoids that mismatch entirely.
     *
     * @var string|false|null
     */
    private $settings_page_hook = null;

    /**
     * Enqueue the settings page's CSS/JS only on the ChargeGuard settings
     * screen — never plugin-wide — and only as properly registered
     * assets, so the admin area works under a strict Content-Security-
     * Policy without needing 'unsafe-inline'.
     *
     * @param string $hook_suffix The current admin page's hook suffix,
     *                            as passed by the admin_enqueue_scripts hook.
     */
    public function enqueue_admin_assets($hook_suffix) {
        if (!$this->settings_page_hook || $hook_suffix !== $this->settings_page_hook) {
            return;
        }

        $version = defined('CHARGEGUARD_VERSION') ? CHARGEGUARD_VERSION : '1.0.0';

        wp_enqueue_style(
            'chargeguard-admin',
            plugin_dir_url(__FILE__) . '../assets/css/admin.css',
            [],
            $version
        );

        wp_enqueue_script(
            'chargeguard-admin-settings',
            plugin_dir_url(__FILE__) . '../assets/js/admin-settings.js',
            ['jquery'],
            $version,
            true
        );

        $current_admin_ip = '';
        if (class_exists('ChargeGuard_Dynamic_Firewall') && method_exists('ChargeGuard_Dynamic_Firewall', 'get_client_ip')) {
            $current_admin_ip = ChargeGuard_Dynamic_Firewall::get_client_ip();
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $current_admin_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        wp_localize_script('chargeguard-admin-settings', 'chargeguardAdmin', [
            // Per-action nonces (WordPress Plugin Security Handbook nonce
            // guidance): each state-changing AJAX action gets its own
            // nonce action string, so a nonce leaked for one action
            // (referrer headers, browser extensions, server/proxy logs)
            // cannot be replayed against a higher-value action like
            // disconnecting the store or changing payment credentials.
            // Read-only/test actions continue to share 'chargeguard_connect_nonce'
            // (kept under its original name for backward compatibility)
            // since leaking one of those only exposes read access the
            // requesting admin already has.
            'nonce'             => wp_create_nonce('chargeguard_connect_nonce'), // shared: read-only actions
            'nonces'            => [
                'connect'         => wp_create_nonce('chargeguard_connect_action_nonce'),
                'disconnect'      => wp_create_nonce('chargeguard_disconnect_nonce'),
                'whitelistAdd'    => wp_create_nonce('chargeguard_whitelist_add_nonce'),
                'whitelistDelete' => wp_create_nonce('chargeguard_whitelist_delete_nonce'),
                'blacklistAdd'    => wp_create_nonce('chargeguard_blacklist_add_nonce'),
                'blacklistDelete' => wp_create_nonce('chargeguard_blacklist_delete_nonce'),
                'webhookSave'     => wp_create_nonce('chargeguard_webhook_save_nonce'),
                'paypalSave'      => wp_create_nonce('chargeguard_paypal_save_nonce'),
                'stripeSave'      => wp_create_nonce('chargeguard_stripe_save_nonce'),
                'geoOverrideSave' => wp_create_nonce('chargeguard_geo_override_save_nonce'),
                'storeAdd'        => wp_create_nonce('chargeguard_store_add_nonce'),
                'storeRename'     => wp_create_nonce('chargeguard_store_rename_nonce'),
                'storeDeactivate' => wp_create_nonce('chargeguard_store_deactivate_nonce'),
            ],
            'currentIp'         => $current_admin_ip,
            'merchantId'        => get_option('chargeguard_merchant_id'),
            'isConnected'       => (bool) chargeguard_get_secret_option('chargeguard_api_key'),
            'hasPendingConnect' => (bool) get_transient('chargeguard_pending_connect'),
        ]);
    }

    public function register_settings() {
        register_setting('chargeguard_firewall_settings', 'chargeguard_enable_firewall', 'intval');
        register_setting('chargeguard_firewall_settings', 'chargeguard_firewall_block_duration', 'intval');
        // Legacy toggle — kept ONLY as the migration source read once by
        // get_client_ip()'s backward-compat shim. No longer written by
        // this settings page once chargeguard_proxy_trust_mode exists.
        register_setting('chargeguard_firewall_settings', 'chargeguard_trust_proxy_headers', 'intval');

        register_setting('chargeguard_firewall_settings', 'chargeguard_proxy_trust_mode', [
            'type'              => 'string',
            'sanitize_callback' => function ($value) {
                return in_array($value, ['off', 'cloudflare', 'custom', 'both'], true) ? $value : 'off';
            },
            'default' => 'off',
        ]);
        register_setting('chargeguard_firewall_settings', 'chargeguard_trusted_proxy_cidrs', [
            'type'              => 'string',
            'sanitize_callback' => 'sanitize_textarea_field',
            'default'           => '',
        ]);
        
        // Auto-block on fraud decision
        register_setting( 'chargeguard_autoblock_settings', 'chargeguard_auto_block', [
            'type'              => 'string',
            'sanitize_callback' => function( $value ) { return $value === 'yes' ? 'yes' : 'no'; },
            'default'           => 'no',
        ] );
        register_setting( 'chargeguard_autoblock_settings', 'chargeguard_block_min_amount', [
            'type'              => 'number',
            'sanitize_callback' => 'floatval',
            'default'           => 0,
        ] );

        // Auto-refund — separate, opt-in, and deliberately more dangerous
        // than auto-block: it moves real money. Only ever takes effect
        // when chargeguard_auto_block is ALSO 'yes' — see
        // chargeguard_maybe_block_order() in trait-chargeguard-auto-block.php,
        // which gates the entire method (including the refund branch) on
        // that flag first.
        register_setting( 'chargeguard_autoblock_settings', 'chargeguard_auto_refund', [
            'type'              => 'string',
            'sanitize_callback' => function( $value ) { return $value === 'yes' ? 'yes' : 'no'; },
            'default'           => 'no',
        ] );

        // ── API-Unavailable Fallback Behavior ───────────────────────────
        // Governs what ChargeGuard_Dynamic_Firewall::resolve_api_unavailable_decision()
        // does at checkout when the backend cannot be reached (circuit
        // breaker open, or a single failed/5xx request). Default is the
        // safer 'local_checks' mode, not the legacy unconditional approve.
        register_setting( 'chargeguard_apidown_settings', 'chargeguard_api_down_behavior', [
            'type'              => 'string',
            'sanitize_callback' => function( $value ) {
                $allowed = [ 'block_all', 'local_checks', 'allow_all' ];
                return in_array( $value, $allowed, true ) ? $value : 'local_checks';
            },
            'default'           => 'local_checks',
        ] );
        // Separate, explicit opt-in required before 'allow_all' takes
        // effect — see resolve_api_unavailable_decision(). A merchant
        // cannot end up in fail-open-everything mode by a single dropdown
        // click alone.
        register_setting( 'chargeguard_apidown_settings', 'chargeguard_api_down_allow_all_ack', [
            'type'              => 'string',
            'sanitize_callback' => function( $value ) { return $value === '1' ? '1' : '0'; },
            'default'           => '0',
        ] );
        register_setting( 'chargeguard_apidown_settings', 'chargeguard_api_down_rate_limit', [
            'type'              => 'number',
            'sanitize_callback' => function( $value ) {
                $v = intval( $value );
                return ( $v >= 1 && $v <= 50 ) ? $v : 3;
            },
            'default'           => 3,
        ] );
    }
    public function ajax_verify_key() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');

        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'No API key found.']);
        }

        // Migrated off the raw wp_remote_get()/GET /auth/verify path onto
        // the same ChargeGuard_API_Client::verify_key() every other
        // consumer of this check already uses (settings_page()'s
        // plan-gating call). This calls the richer GET /risk/verify-key
        // endpoint and removes the last hardcoded backend URL/endpoint
        // pair in this file — consistency with every other migrated
        // ajax_* handler, not just this one.
        $result = (new ChargeGuard_API_Client())->verify_key();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }

        wp_send_json_success(['message' => '✓ API key is valid.']);
    }

    public function ajax_check_for_updates() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        if (!class_exists('ChargeGuard_Plugin_Updater')) {
            wp_send_json_error(['message' => 'Updater not available.']);
        }
        ChargeGuard_Plugin_Updater::force_check();
        wp_send_json_success(['message' => 'Checked for updates.']);
    }

    /**
     * Show a persistent admin notice if the post-connect signing self-test
     * failed, so the merchant isn't relying solely on the one-time message
     * shown at the moment they clicked Connect.
     */
    public function maybe_show_signing_self_test_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        if (!chargeguard_get_secret_option('chargeguard_api_key')) {
            return; // Not connected — nothing to warn about.
        }
        $status = get_option('chargeguard_signing_self_test', []);
        if (empty($status) || ($status['status'] ?? '') !== 'failed') {
            return;
        }
        ?>
        <div class="notice notice-error">
            <p>
                <strong>ChargeGuard:</strong>
                <?php esc_html_e('Your store is connected, but ChargeGuard could not verify that request signing is working correctly. Fraud evaluations may be silently rejected by the server. Please disconnect and reconnect your store; if the problem persists, contact ChargeGuard support.', 'chargeguard-woocommerce'); ?>
            </p>
        </div>
        <?php
    }

    /**
     * Show a persistent admin notice if any Stripe/PayPal secret failed
     * to decrypt on last read (see chargeguard_get_secret_option()).
     * Mirrors maybe_show_signing_self_test_notice(): a single option
     * (chargeguard_secret_decrypt_failures) is the source of truth, so
     * the notice disappears automatically the moment the merchant
     * re-enters a working credential — no separate "resolved" action
     * needed.
     */
    public function maybe_show_secret_decrypt_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        $failures = get_option('chargeguard_secret_decrypt_failures', []);
        if (empty($failures) || !is_array($failures)) {
            return;
        }

        $labels = [
            'chargeguard_stripe_secret_key'      => __('Stripe secret key', 'chargeguard-woocommerce'),
            'chargeguard_stripe_webhook_secret'  => __('Stripe webhook signing secret', 'chargeguard-woocommerce'),
            'chargeguard_paypal_client_secret'   => __('PayPal client secret', 'chargeguard-woocommerce'),
            'chargeguard_api_key'                => __('ChargeGuard API key', 'chargeguard-woocommerce'),
            'chargeguard_webhook_secret'         => __('ChargeGuard webhook secret', 'chargeguard-woocommerce'),
            'chargeguard_api_signing_secret'     => __('ChargeGuard signing secret', 'chargeguard-woocommerce'),
        ];

        $broken = [];
        foreach (array_keys($failures) as $option_name) {
            $broken[] = $labels[$option_name] ?? $option_name;
        }
        $broken_list = implode(', ', $broken);
        ?>
        <div class="notice notice-error is-dismissible">
            <p>
                <strong>ChargeGuard:</strong>
                <?php
                printf(
                    esc_html__('Your ChargeGuard %s could not be decrypted — this can happen after a site migration or host change that regenerates your WordPress secret keys. Payment protection for the affected gateway is currently disabled. Please re-enter your credentials in the ChargeGuard settings under Stripe/PayPal Integration to restore protection.', 'chargeguard-woocommerce'),
                    esc_html($broken_list)
                );
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * Warn the merchant when the AES-256-GCM key protecting their
     * Stripe/PayPal/ChargeGuard secrets is derived from a value
     * WordPress itself stored in wp_options (wp_salt('auth')'s database
     * fallback), rather than from wp-config.php constants or a dedicated
     * CHARGEGUARD_ENCRYPTION_KEY. In that configuration, a
     * database-only compromise exposes both the ciphertext and the key
     * material together, defeating the purpose of at-rest encryption.
     *
     * Silent whenever either escape hatch is in place.
     */
    public function maybe_show_key_derivation_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        if (defined('AUTH_KEY') && AUTH_KEY) {
            return; // Salts are hardcoded in wp-config.php — key material isn't in the DB.
        }
        if (defined('CHARGEGUARD_ENCRYPTION_KEY') && CHARGEGUARD_ENCRYPTION_KEY) {
            return; // Merchant has already opted into a DB-independent key.
        }
        ?>
        <div class="notice notice-warning is-dismissible">
            <p>
                <strong>ChargeGuard:</strong>
                <?php esc_html_e('Your site does not have AUTH_KEY/AUTH_SALT hardcoded in wp-config.php, so WordPress generated and stored them in the database itself. Because ChargeGuard encrypts your Stripe/PayPal/API secrets using a key derived from that same value, a database-only compromise (e.g. a leaked backup) could expose both your encrypted secrets and the key needed to decrypt them, together. To fix this, either add AUTH_KEY and AUTH_SALT to wp-config.php, or define a dedicated CHARGEGUARD_ENCRYPTION_KEY constant (a 64-character random hex string) — ChargeGuard will use it automatically and this notice will disappear.', 'chargeguard-woocommerce'); ?>
            </p>
        </div>
        <?php
    }

    /**
     * Warn the merchant when the Cloudflare Turnstile site key powering the
     * Connect flow's bot-verification widget is still Cloudflare's public
     * "always passes" test key (1x00000000000000000000AA). With this key,
     * the Turnstile widget renders and looks functional, but every
     * challenge succeeds unconditionally — the Connect flow's first-line
     * bot mitigation is silently a no-op. See CHARGEGUARD_TURNSTILE_SITE_KEY
     * in the main plugin file.
     *
     * Silent the moment a real site key is defined.
     */
    public function maybe_show_turnstile_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        if (!defined('CHARGEGUARD_TURNSTILE_SITE_KEY') || CHARGEGUARD_TURNSTILE_SITE_KEY !== '1x00000000000000000000AA') {
            return; // A real site key is configured — nothing to warn about.
        }
        ?>
        <div class="notice notice-warning is-dismissible">
            <p>
                <strong>ChargeGuard:</strong>
                <?php esc_html_e('The Connect flow is currently using Cloudflare\'s public Turnstile TEST key, which always passes regardless of whether the visitor is a human or a bot — bot protection on the Connect request is not active. To fix this, add your real Turnstile site key to wp-config.php (above the "That\'s all, stop editing!" comment): define(\'CHARGEGUARD_TURNSTILE_SITE_KEY\', \'your_real_site_key_here\'); This notice will disappear automatically once a real key is set.', 'chargeguard-woocommerce'); ?>
            </p>
        </div>
        <?php
    }

    public function ajax_connect() {
        // Own nonce action — initiating a connect request emails an
        // address and starts binding this store to a ChargeGuard
        // account; a nonce that only authorizes read-only status
        // checks must not also authorize this.
        check_ajax_referer('chargeguard_connect_action_nonce', 'nonce');

        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $email = sanitize_email(wp_unslash($_POST['email'] ?? ''));
        if (!is_email($email)) {
            wp_send_json_error(['message' => 'Please enter a valid email address.']);
        }

        // L2 fix: lightweight per-user transient throttle, matching the
        // pattern already used in ajax_check_fingerprint() (1 request per
        // window via get_transient()/set_transient()). This does not
        // replace the backend's own 15-minute-attempt rate limit — it
        // exists purely to stop a single WordPress request cycle (e.g. a
        // compromised Shop Manager account, or a script replaying a
        // captured nonce) from firing the confirmation email endpoint in
        // rapid succession before the backend's own limiter is ever
        // reached. Keyed on the current user ID rather than IP, since
        // this action already requires an authenticated manage_woocommerce
        // session — the user ID is the more precise identity for this
        // action's own throttle.
        $connect_rl_key = 'cg_connect_rl_' . get_current_user_id();
        if (get_transient($connect_rl_key)) {
            wp_send_json_error(['message' => 'Please wait a moment before trying again.']);
        }
        set_transient($connect_rl_key, 1, 30);

        // The backend's /connect requires a Cloudflare Turnstile token
        // proving this request originated from a real browser. This PHP
        // handler runs server-to-server and cannot solve that challenge
        // itself — the token is produced by the Turnstile widget rendered
        // on this settings page (see settings_page()) and relayed here by
        // the browser, exactly like the email address is.
        // SECURITY BOUNDARY NOTE (informational finding, pre-launch audit):
        // The check below confirms the token is PRESENT, not that it is VALID.
        // This plugin cannot verify Turnstile tokens itself, and must not try to —
        // that would require the Turnstile *secret* key, which must never be
        // configured on, stored in, or exposed to WordPress/PHP. WordPress
        // (plugins, DB backups, hosting-panel access, etc.) is a wider and less
        // controlled trust boundary than the ChargeGuard backend, so secret
        // material that gates a security decision stays server-side only —
        // the same principle already applied to chargeguard_api_signing_secret
        // and CHARGEGUARD_ENCRYPTION_KEY elsewhere in this file.
        //
        // Real verification is the responsibility of the ChargeGuard backend's
        // POST /api/auth/connect handler, which MUST, on every request:
        //   1. Call https://challenges.cloudflare.com/turnstile/v0/siteverify
        //      with this token and the Turnstile secret key.
        //   2. Check that the response's `success` field is true (and ideally
        //      that `hostname`/`action` match expectations).
        //   3. Reject the connect request (do not issue a connectRequestId) if
        //      verification fails.
        // If the backend does not do this, Turnstile here provides no real bot
        // mitigation — it becomes a cosmetic checkbox with no security value.
        $turnstile_token = sanitize_text_field(wp_unslash($_POST['turnstileToken'] ?? ''));
        if (!$turnstile_token) {
            wp_send_json_error(['message' => 'Security check not completed. Please refresh the page and try again.']);
        }

        $site_url = get_site_url();

        $response = wp_remote_post('https://chargeguard-api.onrender.com/api/auth/connect', [
            'timeout' => 15,
            'headers' => [
                'Content-Type'   => 'application/json',
                'x-store-domain' => wp_parse_url( home_url(), PHP_URL_HOST ),
            ],
            'body'    => json_encode([
                'email'          => $email,
                'siteUrl'        => $site_url,
                'turnstileToken' => $turnstile_token,
            ]),
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard. Check your connection.']);
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code === 429) {
            wp_send_json_error(['message' => $body['error'] ?? 'Too many attempts. Please wait before trying again.']);
        }

        if ($code !== 200 || empty($body['connectRequestId']) || !is_string($body['connectRequestId'])) {
            error_log('ChargeGuard: /auth/connect returned HTTP ' . $code . ' with an unexpected body. Keys present: ' . (is_array($body) ? implode(', ', array_keys($body)) : 'none (body was not valid JSON)'));
            wp_send_json_error(['message' => 'Connection failed. Please try again.']);
        }

        // Pending — not yet confirmed. Stored as a transient, not an
        // option, so it naturally expires and vanishes if the merchant
        // never clicks the email link, tracking the backend's own
        // 15-minute connect-token window with a small buffer. This also
        // lets settings_page() detect and resume an in-flight request
        // across a browser refresh instead of losing all state.
        //
        set_transient('chargeguard_pending_connect', [
            'request_id' => $body['connectRequestId'],
            'email'      => $email,
            'issued_at'  => time(),
        ], 20 * MINUTE_IN_SECONDS);

        wp_send_json_success([
            'status'           => 'pending',
            'connectRequestId' => $body['connectRequestId'],
            'email'            => $email,
        ]);
    }

    /**
     * Polled by the browser (see settings_page() JS) while waiting for
     * the merchant to click the confirmation link in their email. Mirrors
     * OAuth 2.0 Device Authorization Grant (RFC 8628) polling semantics
     * on the client side, matching /connect/status's design on the
     * backend.
     */
    public function ajax_connect_poll() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');

        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $pending = get_transient('chargeguard_pending_connect');
        if (!$pending || empty($pending['request_id'])) {
            wp_send_json_error(['status' => 'expired', 'message' => 'No pending connection request found. Please start again.']);
        }

        $response = wp_remote_get(
            'https://chargeguard-api.onrender.com/api/auth/connect/status?requestId=' . urlencode($pending['request_id']),
            ['timeout' => 10]
        );

        if (is_wp_error($response)) {
            // Transient network hiccup — keep polling rather than fail
            // the merchant's connection attempt on one bad check.
            wp_send_json_success(['status' => 'pending']);
        }

        $body   = json_decode(wp_remote_retrieve_body($response), true);
        $status = $body['status'] ?? 'pending';

        if ($status === 'expired') {
            delete_transient('chargeguard_pending_connect');
            wp_send_json_success(['status' => 'expired']);
        }

        if ($status !== 'active') {
            wp_send_json_success(['status' => 'pending']);
        }

        $required_keys = ['apiKey', 'merchantId', 'webhookSecret'];
        $is_valid_body = is_array($body);
        if ($is_valid_body) {
            foreach ($required_keys as $key) {
                if (empty($body[$key]) || !is_string($body[$key])) {
                    $is_valid_body = false;
                    break;
                }
            }
        }

        if (!$is_valid_body) {
            error_log('ChargeGuard: /auth/connect/status returned status=active with an invalid or incomplete body. Keys present: ' . (is_array($body) ? implode(', ', array_keys($body)) : 'none (body was not valid JSON)'));
            delete_transient('chargeguard_pending_connect');
            wp_send_json_error(['status' => 'failed', 'message' => 'An unexpected error occurred while connecting to ChargeGuard. Please try again.']);
        }

        chargeguard_update_secret_option('chargeguard_api_key', sanitize_text_field($body['apiKey']));
        update_option('chargeguard_merchant_id',    sanitize_text_field($body['merchantId']));
        chargeguard_update_secret_option('chargeguard_webhook_secret', sanitize_text_field($body['webhookSecret']));
        update_option('chargeguard_connected_email', sanitize_email($pending['email']));

        // No separate api_signing_secret — the backend was never built to
        // accept or confirm one, so signing uses webhookSecret exclusively
        // (see class-api-client.php generate_hmac()). This delete is
        // defensive cleanup for any install that still has a leftover
        // value from before this cleanup.
        delete_option('chargeguard_api_signing_secret');

        $this->register_woocommerce_webhook($body['webhookSecret']);

        $self_test_client = new ChargeGuard_API_Client();
        $self_test_result = $self_test_client->self_test();

        delete_transient('chargeguard_pending_connect');

        if (is_wp_error($self_test_result)) {
            update_option('chargeguard_signing_self_test', [
                'status'  => 'failed',
                'message' => $self_test_result->get_error_message(),
                'time'    => time(),
            ]);
            error_log('ChargeGuard: post-connect signing self-test failed: ' . $self_test_result->get_error_message());
            wp_send_json_success([
                'status'        => 'active',
                'email'         => $pending['email'],
                'selfTestOk'    => false,
                'selfTestError' => __('Connected, but ChargeGuard could not verify request signing. Fraud protection may not be active — check the notice at the top of this page.', 'chargeguard-woocommerce'),
            ]);
        }

        update_option('chargeguard_signing_self_test', ['status' => 'ok', 'time' => time()]);

        wp_send_json_success(['status' => 'active', 'email' => $pending['email'], 'selfTestOk' => true]);
    }

    public function ajax_disconnect() {
        // Own nonce action — disconnects the store's fraud protection
        // entirely; must not be reachable via a leaked read-only nonce.
        check_ajax_referer('chargeguard_disconnect_nonce', 'nonce');

        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        delete_option('chargeguard_api_key');
        delete_option('chargeguard_merchant_id');
        delete_option('chargeguard_webhook_secret');
        delete_option('chargeguard_api_signing_secret');
        delete_option('chargeguard_connected_email');
        delete_option('chargeguard_signing_self_test');

        // Disable Stripe/PayPal enrichment so their webhook handlers stop
        // processing and forwarding card data even if the merchant left
        // those webhooks configured directly in the Stripe/PayPal dashboards.
        update_option('chargeguard_stripe_enabled', '0');
        update_option('chargeguard_paypal_enabled', '0');

        // حذف الـ webhook
        $this->delete_woocommerce_webhook();

        wp_send_json_success();
    }

    public function ajax_whitelist_get() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $result = (new ChargeGuard_API_Client())->whitelist_get();
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['entries' => $result['entries'] ?? []]);
    }

    public function ajax_whitelist_add() {
        check_ajax_referer('chargeguard_whitelist_add_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $type   = sanitize_text_field(wp_unslash($_POST['type']   ?? ''));
        $value  = sanitize_text_field(wp_unslash($_POST['value']  ?? ''));
        $reason = sanitize_text_field(wp_unslash($_POST['reason'] ?? ''));
        if (!$type || !$value) {
            wp_send_json_error(['message' => 'Type and value are required.']);
        }
        $result = (new ChargeGuard_API_Client())->whitelist_add($type, $value, $reason);
        if (is_wp_error($result)) {
            if ($result->get_error_code() === 'api_conflict') {
                wp_send_json_error(['message' => 'This entry already exists in the safe list.']);
            }
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['entry' => $result['entry'] ?? []]);
    }

    public function ajax_whitelist_delete() {
        check_ajax_referer('chargeguard_whitelist_delete_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        $id      = sanitize_text_field(wp_unslash($_POST['id'] ?? ''));
        if (!$api_key || !$id) {
            wp_send_json_error(['message' => 'Missing required data.']);
        }
        $result = (new ChargeGuard_API_Client())->whitelist_delete($id);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => 'Failed to delete entry.']);
        }
        wp_send_json_success();
    }

    public function ajax_blacklist_get() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $result = (new ChargeGuard_API_Client())->blacklist_get();
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['entries' => $result['entries'] ?? []]);
    }

    public function ajax_blacklist_add() {
        check_ajax_referer('chargeguard_blacklist_add_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $type   = sanitize_text_field(wp_unslash($_POST['type']   ?? ''));
        $value  = sanitize_text_field(wp_unslash($_POST['value']  ?? ''));
        $reason = sanitize_text_field(wp_unslash($_POST['reason'] ?? ''));
        if (!$type || !$value) {
            wp_send_json_error(['message' => 'Type and value are required.']);
        }
        $result = (new ChargeGuard_API_Client())->blacklist_add($type, $value, $reason);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['entry' => $result['entry'] ?? []]);
    }

    public function ajax_blacklist_delete() {
        check_ajax_referer('chargeguard_blacklist_delete_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        $id      = sanitize_text_field(wp_unslash($_POST['id'] ?? ''));
        if (!$api_key || !$id) {
            wp_send_json_error(['message' => 'Missing required data.']);
        }
        $result = (new ChargeGuard_API_Client())->blacklist_delete($id);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => 'Failed to delete entry.']);
        }
        wp_send_json_success();
    }

    public function ajax_webhook_save() {
        check_ajax_referer('chargeguard_webhook_save_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $webhook_url  = sanitize_text_field(wp_unslash($_POST['webhook_url']  ?? ''));
        $webhook_type = sanitize_text_field(wp_unslash($_POST['webhook_type'] ?? 'custom'));
        if (!in_array($webhook_type, ['slack', 'discord', 'custom'])) {
            $webhook_type = 'custom';
        }

        // Server-side URL validation — the client-side JS check is only a
        // UX convenience and is not trusted here (see M4 hardening).
        if ($webhook_url === '') {
            wp_send_json_error(['message' => 'Please enter a webhook URL.']);
        }

        $webhook_url = esc_url_raw($webhook_url);
        $parts       = wp_parse_url($webhook_url);

        if (empty($webhook_url) || empty($parts) || empty($parts['host'])) {
            wp_send_json_error(['message' => 'That does not look like a valid URL.']);
        }

        if (($parts['scheme'] ?? '') !== 'https') {
            wp_send_json_error(['message' => 'Only HTTPS webhook URLs are allowed.']);
        }

        // $resolved_ip is captured here, at the exact moment of
        // validation, rather than re-resolved afterward — see the
        // chargeguard_host_is_private_or_reserved() docblock. This is
        // the IP that was actually checked against the private/reserved
        // range below; forwarding it to the backend lets it either pin
        // delivery to this address or re-resolve at send time and
        // reject if the hostname has since been repointed (DNS
        // rebinding). This does not itself close the TOCTOU gap — the
        // backend, which makes the real outbound request, must be the
        // one to act on this value — but it gives the backend the
        // information it needs to do so, which the plugin previously
        // discarded entirely after this check.
        $resolved_ip = '';
        if (chargeguard_host_is_private_or_reserved($parts['host'], $resolved_ip)) {
            wp_send_json_error(['message' => 'This webhook URL points to an internal or reserved address and cannot be used.']);
        }

        $result = (new ChargeGuard_API_Client())->webhook_save($webhook_url, $webhook_type, $resolved_ip);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success();
    }

    public function ajax_webhook_test() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $result = (new ChargeGuard_API_Client())->webhook_test();
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success();
    }

    public function ajax_webhook_status() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $result = (new ChargeGuard_API_Client())->webhook_status();
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success([
            'webhookUrl'          => $result['webhookUrl']          ?? '',
            'webhookType'         => $result['webhookType']         ?? '',
            'webhookLastStatus'   => $result['webhookLastStatus']   ?? '',
            'webhookLastSentAt'   => $result['webhookLastSentAt']   ?? '',
            'webhookFailureCount' => $result['webhookFailureCount'] ?? 0,
        ]);
    }

    private function register_woocommerce_webhook($secret) {
        $existing = get_option('chargeguard_webhook_id');
        if ($existing) return;

        $webhook_url = 'https://chargeguard-api.onrender.com/api/risk/woocommerce-webhook';

        $webhook = new WC_Webhook();
        $webhook->set_name('ChargeGuard Order Monitor');
        $webhook->set_topic('order.created');
        $webhook->set_delivery_url($webhook_url);
        // STORAGE NOTE (informational, F10): this secret is persisted by
        // WooCommerce core's own WC_Webhook storage (typically wp_postmeta),
        // not by this plugin's ChargeGuard_Secret_Crypto encryption layer —
        // WooCommerce core has historically stored webhook secrets in
        // plaintext. This is upstream behavior outside this plugin's
        // control; ChargeGuard does not intercept, wrap, or re-encrypt data
        // WooCommerce core itself owns the persistence of. Documented here
        // for transparency: a DB-level compromise exposes this value
        // regardless of how well chargeguard_* options are encrypted.
        $webhook->set_secret($secret);
        $webhook->set_status('active');
        $webhook->save();

        update_option('chargeguard_webhook_id', $webhook->get_id());
    }

    private function delete_woocommerce_webhook() {
        $webhook_id = get_option('chargeguard_webhook_id');
        if (!$webhook_id) return;

        $webhook = new WC_Webhook($webhook_id);
        $webhook->delete(true);
        delete_option('chargeguard_webhook_id');
    }

    public function ajax_geo_overrides_get() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $result = (new ChargeGuard_API_Client())->geo_overrides_get();
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success([
            'countryOverrides'   => $result['countryOverrides']   ?? [],
            'availableCountries' => $result['availableCountries'] ?? [],
            'summary'            => $result['summary']            ?? [],
        ]);
    }

    public function ajax_geo_override_save() {
        check_ajax_referer('chargeguard_geo_override_save_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $country_code = sanitize_text_field(wp_unslash($_POST['country_code'] ?? ''));
        $override     = sanitize_text_field(wp_unslash($_POST['override']      ?? ''));
        if (!$country_code || !$override) {
            wp_send_json_error(['message' => 'country_code and override are required.']);
        }
        $allowed_overrides = ['allow', 'escalate', 'smart'];
        if (!in_array($override, $allowed_overrides, true)) {
            wp_send_json_error(['message' => 'Invalid override value.']);
        }
        $result = (new ChargeGuard_API_Client())->geo_override_save($country_code, $override);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success([
            'countryOverrides' => $result['countryOverrides'] ?? [],
            'warnings'         => $result['warnings']         ?? [],
        ]);
    }

    public function ajax_stores_get() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $result = (new ChargeGuard_API_Client())->stores_get();
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['stores' => $result['stores'] ?? []]);
    }

    public function ajax_store_add() {
        check_ajax_referer('chargeguard_store_add_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $store_url = sanitize_text_field(wp_unslash($_POST['store_url'] ?? ''));
        $label     = sanitize_text_field(wp_unslash($_POST['label']     ?? ''));
        if (!$store_url) {
            wp_send_json_error(['message' => 'A store URL or domain is required.']);
        }
        $result = (new ChargeGuard_API_Client())->store_add($store_url, $label);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['store' => $result['store'] ?? [], 'reactivated' => $result['reactivated'] ?? false]);
    }

    public function ajax_store_rename() {
        check_ajax_referer('chargeguard_store_rename_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $id    = sanitize_text_field(wp_unslash($_POST['id']    ?? ''));
        $label = sanitize_text_field(wp_unslash($_POST['label'] ?? ''));
        if (!$id || $label === '') {
            wp_send_json_error(['message' => 'id and label are required.']);
        }
        $result = (new ChargeGuard_API_Client())->store_update($id, ['label' => $label]);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['store' => $result['store'] ?? []]);
    }

    public function ajax_store_deactivate() {
        check_ajax_referer('chargeguard_store_deactivate_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $id = sanitize_text_field(wp_unslash($_POST['id'] ?? ''));
        if (!$id) {
            wp_send_json_error(['message' => 'id is required.']);
        }
        $result = (new ChargeGuard_API_Client())->store_deactivate($id);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success();
    }

    public function ajax_store_reactivate() {
        check_ajax_referer('chargeguard_store_deactivate_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $id = sanitize_text_field(wp_unslash($_POST['id'] ?? ''));
        if (!$id) {
            wp_send_json_error(['message' => 'id is required.']);
        }
        $result = (new ChargeGuard_API_Client())->store_update($id, ['isActive' => true]);
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }
        wp_send_json_success(['store' => $result['store'] ?? []]);
    }

    /**
     * Resolves whether the connected merchant's plan currently entitles
     * them to Pro-or-above features, reusing the same 5-minute transient
     * cache settings_page() populates (chargeguard_merchant_plan_cache) so
     * the common case — a merchant who just loaded the settings page, then
     * submitted a form — costs no extra backend round-trip. Falls back to
     * a fresh verify_key() call, cached the same way, when the transient
     * is cold (e.g. a direct AJAX call with no recent page load). Fails
     * closed (treats the merchant as NOT Pro) if verify_key() itself
     * fails, so a backend outage can never be used to bypass this gate.
     *
     * @return bool
     */
    private function merchant_is_pro_or_above_cached() {
        $cached_plan = get_transient( 'chargeguard_merchant_plan_cache' );
        if ( $cached_plan === false ) {
            $verify_result = ( new ChargeGuard_API_Client() )->verify_key();
            if ( ! is_wp_error( $verify_result ) && ! empty( $verify_result['plan'] ) ) {
                $cached_plan = $verify_result['plan'];
                set_transient( 'chargeguard_merchant_plan_cache', $cached_plan, self::PLAN_CACHE_TTL );
            } else {
                $cached_plan = 'starter'; // fail closed — never silently allow a Pro-gated save
            }
        }
        return in_array( $cached_plan, [ 'pro', 'agency' ], true );
    }

    public function ajax_paypal_save() {
        check_ajax_referer( 'chargeguard_paypal_save_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_send_json_error( [ 'message' => 'unauthorized' ], 403 );
        }

        // Plan gate (CWE-862 fix): settings_page() soft-locks the PayPal
        // Integration card behind $merchant_is_pro_or_above, but that check
        // only decides what settings_page() renders — it was never enforced
        // here, where credentials are actually persisted. A Starter tenant
        // calling this action directly (DevTools, a script, or a replayed
        // request) could previously save working PayPal credentials even
        // though real-time PayPal alerts never fire for their plan (the
        // backend's notifyPaypalAlert() already gates delivery via
        // isProOrAbove() — this closes the matching gap on the write side,
        // so a Starter tenant can no longer configure state for a feature
        // their plan doesn't entitle them to use).
        if ( ! $this->merchant_is_pro_or_above_cached() ) {
            wp_send_json_error( [ 'message' => 'PayPal real-time alerts require a Pro plan or above. Please upgrade to configure PayPal integration.' ] );
        }

        $client_id     = isset( $_POST['client_id'] )     ? sanitize_text_field( wp_unslash( $_POST['client_id'] ) )     : '';
        $client_secret = isset( $_POST['client_secret'] ) ? sanitize_text_field( wp_unslash( $_POST['client_secret'] ) ) : '';
        $webhook_id    = isset( $_POST['webhook_id'] )    ? sanitize_text_field( wp_unslash( $_POST['webhook_id'] ) )    : '';
        $mode          = isset( $_POST['mode'] )          ? sanitize_text_field( wp_unslash( $_POST['mode'] ) )          : 'sandbox';
        $enabled       = isset( $_POST['enabled'] )       ? sanitize_text_field( wp_unslash( $_POST['enabled'] ) )       : '0';

        if ( ! in_array( $mode, [ 'sandbox', 'live' ], true ) ) {
            $mode = 'sandbox';
        }

        // Lightweight sanity check for consistency with ajax_stripe_save()'s
        // format regex, catching the same class of typo at save time instead
        // of at first live use (ajax_paypal_test()). Deliberately NOT a
        // strict prefix/character-class regex like Stripe's: PayPal does not
        // publish a single fixed client-secret format guaranteed stable
        // across Sandbox vs Live apps and account/region variations, so a
        // strict pattern risks rejecting a genuinely valid secret — worse
        // for the merchant than the current one-extra-click delay to
        // discover a real typo. Only checks the two properties that hold
        // for every valid PayPal client secret regardless of format:
        // reasonable minimum length, and no embedded whitespace (a common
        // paste mistake — e.g. copying a trailing space or an extra line).
        if ( ! empty( $client_secret ) && ( strlen( $client_secret ) < 20 || preg_match( '/\s/', $client_secret ) ) ) {
            wp_send_json_error( [ 'message' => 'That does not look like a valid PayPal client secret — it looks too short or contains spaces. Please copy it again from your PayPal app credentials.' ] );
        }

        update_option( 'chargeguard_paypal_client_id',  $client_id );
        if ( ! empty( $client_secret ) ) {
            chargeguard_update_secret_option( 'chargeguard_paypal_client_secret', $client_secret );
        }
        update_option( 'chargeguard_paypal_webhook_id', $webhook_id );
        update_option( 'chargeguard_paypal_mode',          $mode );
        update_option( 'chargeguard_paypal_enabled',       $enabled === '1' ? '1' : '0' );

        // مسح access token المخزّن لإجبار التجديد بالبيانات الجديدة
        delete_transient( 'cg_paypal_access_token_' . md5( $client_id ) );

        wp_send_json_success( [ 'message' => 'paypal settings saved.' ] );
    }

    public function ajax_paypal_test() {
        check_ajax_referer( 'chargeguard_connect_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_send_json_error( [ 'message' => 'unauthorized' ], 403 );
        }

        $client_id     = get_option( 'chargeguard_paypal_client_id' );
        $client_secret = chargeguard_get_secret_option( 'chargeguard_paypal_client_secret' );

        if ( ! $client_id || ! $client_secret ) {
            wp_send_json_error( [ 'message' => 'please save your paypal credentials first.' ] );
        }

        $mode    = get_option( 'chargeguard_paypal_mode', 'sandbox' );
        $api_url = ( $mode === 'live' )
            ? 'https://api-m.paypal.com/v1/oauth2/token'
            : 'https://api-m.sandbox.paypal.com/v1/oauth2/token';

        $response = wp_remote_post( $api_url, [
            'timeout' => 10,
            'headers' => [
                'authorization' => 'basic ' . base64_encode( $client_id . ':' . $client_secret ),
                'content-type'  => 'application/x-www-form-urlencoded',
            ],
            'body' => 'grant_type=client_credentials',
        ] );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( [ 'message' => 'could not reach paypal servers.' ] );
        }

        $code = wp_remote_retrieve_response_code( $response );
        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( $code === 200 && ! empty( $body['access_token'] ) ) {
            wp_send_json_success( [ 'message' => '✓ paypal credentials are valid.' ] );
        } else {
            $error = $body['error_description'] ?? 'invalid credentials.';
            wp_send_json_error( [ 'message' => $error ] );
        }
    }

    public function ajax_stripe_save() {
        check_ajax_referer( 'chargeguard_stripe_save_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $secret_key     = isset( $_POST['secret_key'] )     ? sanitize_text_field( wp_unslash( $_POST['secret_key'] ) )     : '';
        $webhook_secret = isset( $_POST['webhook_secret'] ) ? sanitize_text_field( wp_unslash( $_POST['webhook_secret'] ) ) : '';
        $enabled        = isset( $_POST['enabled'] )        ? sanitize_text_field( wp_unslash( $_POST['enabled'] ) )        : '0';

        // Basic sanity check on key format — real validation happens in ajax_stripe_test().
        if ( ! empty( $secret_key ) && ! preg_match( '/^(sk|rk)_(test|live)_[A-Za-z0-9]+$/', $secret_key ) ) {
            wp_send_json_error( [ 'message' => 'That does not look like a valid Stripe secret key. It should start with sk_test_, sk_live_, rk_test_, or rk_live_.' ] );
        }

        if ( ! empty( $secret_key ) ) {
            chargeguard_update_secret_option( 'chargeguard_stripe_secret_key', $secret_key );
        }
        if ( ! empty( $webhook_secret ) ) {
            chargeguard_update_secret_option( 'chargeguard_stripe_webhook_secret', $webhook_secret );
        }
        update_option( 'chargeguard_stripe_enabled', $enabled === '1' ? '1' : '0' );

        wp_send_json_success( [ 'message' => 'Stripe settings saved.' ] );
    }

    public function ajax_stripe_test() {
        check_ajax_referer( 'chargeguard_connect_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
        }

        $secret_key = chargeguard_get_secret_option( 'chargeguard_stripe_secret_key' );
        if ( ! $secret_key ) {
            wp_send_json_error( [ 'message' => 'Please save your Stripe secret key first.' ] );
        }

        $stripe_init = __DIR__ . '/../vendor/stripe-php/init.php';
        if ( ! file_exists( $stripe_init ) ) {
            wp_send_json_error( [ 'message' => 'Stripe SDK not installed. Run composer install.' ] );
        }
        require_once $stripe_init;

        try {
            \Stripe\Stripe::setApiKey( $secret_key );
            \Stripe\Balance::retrieve();
            wp_send_json_success( [ 'message' => '✓ Stripe credentials are valid.' ] );
        } catch ( \Exception $e ) {
            wp_send_json_error( [ 'message' => $e->getMessage() ] );
        }
    }

    public function settings_page() {
        $is_connected = (bool) chargeguard_get_secret_option('chargeguard_api_key');
        $connected_email = get_option('chargeguard_connected_email', '');

        // Merchant's current plan — fetched from the backend (source of
        // truth for entitlement) and cached briefly so this page load
        // doesn't add an extra API round-trip on every admin request.
        // Used to plan-gate the Notification Channels card below (Gap 2).
        $merchant_plan = 'starter';
        if ($is_connected) {
            $cached_plan = get_transient('chargeguard_merchant_plan_cache');
            if ($cached_plan !== false) {
                $merchant_plan = $cached_plan;
            } else {
                $verify_result = (new ChargeGuard_API_Client())->verify_key();
                if (!is_wp_error($verify_result) && !empty($verify_result['plan'])) {
                    $merchant_plan = $verify_result['plan'];
                    set_transient('chargeguard_merchant_plan_cache', $merchant_plan, self::PLAN_CACHE_TTL);
                }
                // On failure, fall back to 'starter' — fail closed on the
                // UI gate rather than showing a Starter merchant a form
                // the backend will reject.
            }
        }
        $merchant_is_pro_or_above = in_array($merchant_plan, ['pro', 'agency'], true);
        $merchant_is_agency       = ($merchant_plan === 'agency');

        // Cleanup-mode detection: a tenant downgraded from Agency (see
        // subscriptionScheduler.js processGraceToExpired) may still have
        // stale Store rows if server-side deactivation failed, hasn't run
        // yet, or predates that fix. GET /api/stores is intentionally
        // ungated for exactly this reason (routes/stores.js) — this
        // reuses the same signed call ajax_stores_get() already makes, so
        // the Managed Stores card can render a read-only cleanup view
        // instead of vanishing entirely. Only fires for the narrow case
        // (connected, non-Agency) — Agency tenants and disconnected
        // tenants never pay for this extra round trip.
        $has_stale_stores = false;
        if ($is_connected && !$merchant_is_agency) {
            $stores_result = (new ChargeGuard_API_Client())->stores_get();
            if (!is_wp_error($stores_result) && !empty($stores_result['stores'])) {
                $has_stale_stores = true;
            }
        }
        $show_managed_stores_card = $is_connected && ($merchant_is_agency || $has_stale_stores);

        $firewall_enabled    = get_option('chargeguard_enable_firewall', 1);
        $block_duration      = get_option( 'chargeguard_firewall_block_duration', 24 );
        $trust_proxy_headers = get_option( 'chargeguard_trust_proxy_headers', 0 );

        // A prior POST /connect may still be awaiting email confirmation
        // (e.g. the merchant refreshed this page while waiting). Detecting
        // this here lets the UI resume polling immediately instead of
        // showing the entry form again and losing the merchant's place.
        $pending_connect = get_transient('chargeguard_pending_connect');

        // All nonces used by this page's JS are localized via
        // enqueue_admin_assets() -> wp_localize_script('chargeguardAdmin', ...).
        // This method does not create or output any nonce of its own.

        // IP المسؤول الحالي — يستخدم نفس منطق تحليل IP الموجود في الجدار
        // الناري (ChargeGuard_Dynamic_Firewall::get_client_ip()) حتى يتطابق
        // أي IP يضيفه المسؤول هنا تمامًا مع ما يُقارن به وقت تنفيذ الطلب.
        $current_admin_ip = '';
        if (class_exists('ChargeGuard_Dynamic_Firewall') && method_exists('ChargeGuard_Dynamic_Firewall', 'get_client_ip')) {
            $current_admin_ip = ChargeGuard_Dynamic_Firewall::get_client_ip();
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $current_admin_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }
        ?>
        <div class="wrap" id="chargeguard-wrap">
        <h1 style="display:flex;align-items:center;gap:10px;margin-bottom:24px;">
            <span style="font-size:24px;">🛡️</span> ChargeGuard
        </h1>

        <?php if ($is_connected): ?>

            <!-- ✅ Connected State -->
            <div class="cg-card">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                    <div class="cg-status-badge connected" style="margin-bottom:0;">
                        <div class="cg-dot green"></div>
                        Active — Your store is protected
                    </div>
                    <button type="button" id="cg-verify-key-btn" class="button">
                        <?php esc_html_e( 'Verify Key', 'chargeguard-woocommerce' ); ?>
                    </button>
                    <button type="button" id="cg-check-updates-btn" class="button" style="margin-left:8px;">
                        <?php esc_html_e( 'Check for Updates', 'chargeguard-woocommerce' ); ?>
                    </button>
                </div>
                <div id="cg-key-status" style="display:none;font-size:12px;padding:6px 10px;border-radius:6px;margin-bottom:10px;"></div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Connected Account</span>
                    <span class="cg-info-value"><?php echo esc_html($connected_email); ?></span>
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Merchant ID</span>
                    <span class="cg-info-value" style="font-family:monospace;font-size:12px;"><?php echo esc_html(substr(get_option('chargeguard_merchant_id'), 0, 16) . '...'); ?></span>
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Webhook</span>
                    <span class="cg-info-value" style="color:#16a34a;">✓ Configured automatically</span>
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Firewall</span>
                    <span class="cg-info-value" style="color:#16a34a;">✓ Active</span>
                </div>
                <button class="cg-btn cg-btn-danger" id="cg-disconnect-btn">
                    Disconnect Store
                </button>
            </div>

        <?php else: ?>

            <!-- 🔌 Connect State -->
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
            <div class="cg-card">
                <div class="cg-status-badge disconnected">
                    <div class="cg-dot gray"></div>
                    Not Connected
                </div>

                <div class="cg-steps">
                    <div class="cg-step <?php echo $pending_connect ? 'done' : 'active'; ?>" id="cg-step-1">① Enter Email</div>
                    <div class="cg-step <?php echo $pending_connect ? 'active' : ''; ?>" id="cg-step-2">② Confirm Email</div>
                    <div class="cg-step" id="cg-step-3">③ Protected</div>
                </div>

                <div id="cg-connect-form" <?php echo $pending_connect ? 'style="display:none;"' : ''; ?>>
                    <p style="color:#555;font-size:14px;margin-bottom:16px;">
                        Enter the email you used to register at ChargeGuard. We'll send a confirmation link — click it, then this page finishes connecting automatically.
                    </p>

                    <label style="font-size:13px;font-weight:600;color:#333;">
                        Your ChargeGuard Email
                    </label>
                    <input
                        type="email"
                        id="cg-email-input"
                        class="cg-input"
                        placeholder="you@yourstore.com"
                        autocomplete="email"
                        value="<?php echo esc_attr($pending_connect['email'] ?? ''); ?>"
                    />

                    <div class="cf-turnstile" id="cg-turnstile-widget"
                         data-sitekey="<?php echo esc_attr( defined('CHARGEGUARD_TURNSTILE_SITE_KEY') ? CHARGEGUARD_TURNSTILE_SITE_KEY : '' ); ?>"
                         data-callback="cgTurnstileCallback"
                         style="margin-top:14px;"></div>

                    <button class="cg-btn cg-btn-primary" id="cg-connect-btn">
                        🔌 Connect ChargeGuard
                    </button>
                </div>

                <div id="cg-connect-pending" <?php echo $pending_connect ? '' : 'style="display:none;"'; ?> style="text-align:center;padding:12px 0;">
                    <div class="cg-spinner" style="border-top-color:#f97316;border-color:#fed7aa;width:22px;height:22px;margin:0 auto 14px;"></div>
                    <p style="color:#555;font-size:14px;margin-bottom:4px;">
                        Check your inbox<?php echo $pending_connect ? ' (' . esc_html($pending_connect['email']) . ')' : ''; ?> and click the confirmation link.
                    </p>
                    <p style="color:#94a3b8;font-size:12px;">This page will finish connecting automatically once you confirm. The link expires in 15 minutes.</p>
                </div>

                <div class="cg-message" id="cg-message"></div>
            </div>

        <?php endif; ?>

        <?php if ($is_connected): ?>
        <!-- Access Control -->
        <div class="cg-card" id="cg-access-control">
            <h3 style="margin:0 0 4px;font-size:15px;">🔐 Access Control</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                <?php esc_html_e( 'Trusted visitors (IP, Email, Card BIN) always bypass security checks, and IP, Email, and Card BIN blocks are enforced on every request. Device ID blocks are a first-line heuristic based on browser fingerprinting, which a determined visitor can alter — the ChargeGuard cloud risk engine is the authoritative check behind every blocked device.', 'chargeguard-woocommerce' ); ?>
            </p>

            <!-- Tab Switcher -->
            <div style="display:flex;gap:0;border-bottom:2px solid #e0e0e0;margin-bottom:20px;">
                <button class="cg-ac-tab cg-ac-active" data-tab="whitelist"
                    style="flex:1;padding:10px;border:none;background:none;cursor:pointer;
                           font-size:13px;font-weight:600;color:#16a34a;
                           border-bottom:2px solid #16a34a;margin-bottom:-2px;">
                    ✅ Always Allow
                </button>
                <button class="cg-ac-tab" data-tab="blacklist"
                    style="flex:1;padding:10px;border:none;background:none;cursor:pointer;
                           font-size:13px;font-weight:600;color:#999;
                           border-bottom:2px solid transparent;margin-bottom:-2px;">
                    🚫 Always Block
                </button>
            </div>

            <!-- Whitelist Panel -->
            <div id="cg-tab-whitelist">
                <!-- Onboarding Banner -->
                <?php if ($current_admin_ip): ?>
                <div id="cg-whitelist-onboarding"
                     style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;
                            padding:12px 16px;margin-bottom:16px;display:flex;
                            align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
                    <span style="font-size:13px;color:#16a34a;">
                        💡 <strong>Quick setup:</strong> Add your IP to never get blocked
                        <span style="font-family:monospace;background:#dcfce7;padding:2px 6px;
                                     border-radius:4px;font-size:12px;">
                            <?php echo esc_html($current_admin_ip); ?>
                        </span>
                    </span>
                    <button id="cg-add-my-ip" class="cg-btn cg-btn-primary"
                            style="margin:0;padding:6px 14px;font-size:12px;">
                        + Add My IP
                    </button>
                </div>
                <?php endif; ?>

                <!-- Add Form -->
                <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start;">
                    <select id="cg-wl-type" class="cg-select" style="min-width:110px;">
                        <option value="IP">IP Address</option>
                        <option value="EMAIL">Email</option>
                        <option value="BIN">Card BIN</option>
                    </select>
                    <input type="text" id="cg-wl-value" class="cg-input"
                           placeholder="e.g. 197.12.34.56"
                           style="flex:1;min-width:160px;margin:0;" />
                    <input type="text" id="cg-wl-reason" class="cg-input"
                           placeholder="Note (optional)"
                           style="flex:1;min-width:120px;margin:0;" />
                    <button id="cg-wl-add" class="cg-btn cg-btn-primary"
                            style="margin:0;white-space:nowrap;">
                        + Add to Safe List
                    </button>
                </div>
                <div id="cg-wl-message" class="cg-message"></div>
                <div id="cg-wl-table-wrap">
                    <p style="color:#999;font-size:13px;">Loading…</p>
                </div>
            </div>

            <!-- Blacklist Panel -->
            <div id="cg-tab-blacklist" style="display:none;">
                <!-- Add Form -->
                <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start;">
                    <select id="cg-bl-type" class="cg-select" style="min-width:130px;">
                        <option value="IP">IP Address</option>
                        <option value="EMAIL">Email</option>
                        <option value="DEVICE_FINGERPRINT">Device ID</option>
                    </select>
                    <input type="text" id="cg-bl-value" class="cg-input"
                           placeholder="e.g. 45.33.32.156"
                           style="flex:1;min-width:160px;margin:0;" />
                    <input type="text" id="cg-bl-reason" class="cg-input"
                           placeholder="Reason (optional)"
                           style="flex:1;min-width:120px;margin:0;" />
                    <button id="cg-bl-add" class="cg-btn"
                            style="margin:0;background:#fef2f2;color:#dc2626;
                                   border:1px solid #fecaca;white-space:nowrap;">
                        🚫 Block This
                    </button>
                </div>
                <div id="cg-bl-message" class="cg-message"></div>
                <div id="cg-bl-table-wrap">
                    <p style="color:#999;font-size:13px;">Loading…</p>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ($is_connected): ?>
        <!-- Geo Risk Intelligence -->
        <div class="cg-card" id="cg-geo-risk-controls">
            <h3 style="margin:0 0 4px;font-size:15px;">🌍 Geo Risk Intelligence</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Fine-tune how ChargeGuard handles transactions from specific regions.
                Smart defaults work for most stores — override only when you have specific business needs.
            </p>

            <!-- Summary Badge -->
            <div id="cg-geo-summary"
                 style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                        padding:12px 16px;margin-bottom:20px;
                        display:flex;align-items:center;justify-content:space-between;">
                <span style="font-size:13px;color:#475569;">
                    ✅ <strong>Smart Protection Active</strong> —
                    <span id="cg-override-count">Loading...</span>
                </span>
                <span style="font-size:11px;color:#94a3b8;">10 regions monitored</span>
            </div>

            <!-- Tier Groups Container -->
            <div id="cg-geo-tiers">
                <p style="color:#999;font-size:13px;">Loading country data...</p>
            </div>

            <!-- Impact Preview -->
            <div id="cg-geo-impact"
                 style="display:none;margin-top:16px;padding:14px 16px;
                        border-radius:8px;border:1px solid #fde68a;background:#fffbeb;">
                <div id="cg-geo-impact-text" style="font-size:13px;color:#92400e;"></div>
                <div style="display:flex;gap:8px;margin-top:10px;">
                    <button id="cg-geo-confirm" class="cg-btn cg-btn-primary"
                            style="margin:0;padding:7px 16px;font-size:13px;">
                        ✓ Apply Change
                    </button>
                    <button id="cg-geo-cancel" class="cg-btn"
                            style="margin:0;padding:7px 16px;font-size:13px;
                                   background:#fff;border:1px solid #ddd;color:#666;">
                        Cancel
                    </button>
                </div>
            </div>

            <div id="cg-geo-message" class="cg-message"></div>
        </div>
        <?php endif; ?>

        <!-- Firewall Settings -->
        <div class="cg-card">
            <h3 style="margin:0 0 4px;font-size:15px;">⚙️ Firewall Settings</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                <?php esc_html_e( 'This controls the local, browser-based device check that runs before checkout. It is a fast first-line heuristic, not a hard security boundary — a visitor can clear cookies or alter their browser fingerprint to get a new identity. The ChargeGuard cloud risk API, which combines this signal with many other factors, makes the final block or allow decision on every order.', 'chargeguard-woocommerce' ); ?>
            </p>
            <form method="post" action="options.php">
                <?php settings_fields('chargeguard_firewall_settings'); ?>
                <div class="cg-info-row">
                    <span class="cg-info-label">Enable Firewall</span>
                    <input type="checkbox" name="chargeguard_enable_firewall" value="1" <?php checked(1, $firewall_enabled); ?> />
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Block Duration (hours)</span>
                    <input type="number" name="chargeguard_firewall_block_duration" value="<?php echo esc_attr($block_duration); ?>" style="width:70px;padding:4px 8px;border:1px solid #ddd;border-radius:6px;" />
                </div>
                <?php
                $proxy_mode = get_option( 'chargeguard_proxy_trust_mode', $trust_proxy_headers ? 'both' : 'off' );
                $custom_cidrs = get_option( 'chargeguard_trusted_proxy_cidrs', '' );
                $detected = ChargeGuard_Trusted_Proxy::looks_like_behind_proxy();
                ?>
                <?php if ( $detected && $proxy_mode === 'off' ) : ?>
                <div class="notice notice-warning inline" style="margin:0 0 14px;">
                    <p style="font-size:13px;">
                        <?php echo $detected === 'cloudflare'
                            ? esc_html__( 'ChargeGuard detected Cloudflare headers on incoming requests, but proxy trust is currently OFF. Every visitor is likely resolving to the same edge IP, disabling IP-based fraud detection. Select "Cloudflare" below to fix this.', 'chargeguard-woocommerce' )
                            : esc_html__( 'ChargeGuard detected forwarded-for headers on incoming requests, but proxy trust is currently OFF. If this site is behind a reverse proxy or load balancer, IP-based fraud detection may be degraded. Configure the correct mode below.', 'chargeguard-woocommerce' ); ?>
                    </p>
                </div>
                <?php endif; ?>

                <div class="cg-info-row" style="align-items:flex-start;">
                    <span class="cg-info-label"><?php esc_html_e( 'IP resolution mode', 'chargeguard-woocommerce' ); ?></span>
                    <select name="chargeguard_proxy_trust_mode" style="min-width:260px;padding:6px 8px;border:1px solid #ddd;border-radius:6px;">
                        <option value="off" <?php selected('off', $proxy_mode); ?>><?php esc_html_e('Direct connection only (default)', 'chargeguard-woocommerce'); ?></option>
                        <option value="cloudflare" <?php selected('cloudflare', $proxy_mode); ?>><?php esc_html_e('Behind Cloudflare', 'chargeguard-woocommerce'); ?></option>
                        <option value="custom" <?php selected('custom', $proxy_mode); ?>><?php esc_html_e('Behind another reverse proxy / load balancer', 'chargeguard-woocommerce'); ?></option>
                        <option value="both" <?php selected('both', $proxy_mode); ?>><?php esc_html_e('Behind Cloudflare AND another proxy', 'chargeguard-woocommerce'); ?></option>
                    </select>
                </div>

                <div class="cg-info-row" style="align-items:flex-start;<?php echo in_array($proxy_mode, ['custom','both'], true) ? '' : 'display:none;'; ?>" id="cg-custom-proxy-row">
                    <span class="cg-info-label"><?php esc_html_e( 'Trusted proxy IP ranges (CIDR, one per line)', 'chargeguard-woocommerce' ); ?></span>
                    <textarea name="chargeguard_trusted_proxy_cidrs" rows="3" style="flex:1;min-width:240px;font-family:monospace;font-size:12px;" placeholder="10.0.0.0/8&#10;203.0.113.5/32"><?php echo esc_textarea( $custom_cidrs ); ?></textarea>
                </div>
                <p style="margin:6px 0 0;font-size:11px;color:#94a3b8;">
                    <?php esc_html_e( 'Only requests whose direct connection IP falls inside these ranges will have their forwarded-for header trusted. This is only safe if your proxy always strips any client-supplied forwarded-for header before adding its own.', 'chargeguard-woocommerce' ); ?>
                </p>
                <?php submit_button('Save Settings', 'secondary', 'submit', false, ['style' => 'margin-top:14px;']); ?>
            </form>
        </div>

        <!-- API-Unavailable Fallback Behavior -->
        <?php
        $api_down_behavior  = get_option('chargeguard_api_down_behavior', 'local_checks');
        $api_down_ack       = get_option('chargeguard_api_down_allow_all_ack', '0');
        $api_down_rate_limit = get_option('chargeguard_api_down_rate_limit', 3);
        ?>
        <div class="cg-card" id="cg-apidown-settings">
            <h3 style="margin:0 0 4px;font-size:15px;">🔌 <?php esc_html_e( 'When the ChargeGuard API Is Unreachable', 'chargeguard-woocommerce' ); ?></h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                <?php esc_html_e( 'Controls what happens to checkout when the fraud-scoring API cannot be reached (e.g. an outage, or the circuit breaker opening after repeated failures).', 'chargeguard-woocommerce' ); ?>
            </p>
            <form method="post" action="options.php">
                <?php settings_fields('chargeguard_apidown_settings'); ?>

                <div class="cg-info-row" style="align-items:flex-start;">
                    <span class="cg-info-label"><?php esc_html_e( 'Fallback Mode', 'chargeguard-woocommerce' ); ?></span>
                    <select name="chargeguard_api_down_behavior" id="cg-apidown-mode" style="min-width:260px;padding:6px 8px;border:1px solid #ddd;border-radius:6px;">
                        <option value="local_checks" <?php selected('local_checks', $api_down_behavior); ?>>
                            <?php esc_html_e( 'Local checks (recommended) — block on device blacklist or IP flood, else allow', 'chargeguard-woocommerce' ); ?>
                        </option>
                        <option value="block_all" <?php selected('block_all', $api_down_behavior); ?>>
                            <?php esc_html_e( 'Block all orders (fail-closed) — safest, but stops taking orders during an outage', 'chargeguard-woocommerce' ); ?>
                        </option>
                        <option value="allow_all" <?php selected('allow_all', $api_down_behavior); ?>>
                            <?php esc_html_e( 'Allow all orders unscored (fail-open) — NOT RECOMMENDED', 'chargeguard-woocommerce' ); ?>
                        </option>
                    </select>
                </div>

                <div class="cg-info-row" style="align-items:flex-start;">
                    <span class="cg-info-label"><?php esc_html_e( 'Local Fallback Rate Limit', 'chargeguard-woocommerce' ); ?></span>
                    <span>
                        <input type="number" min="1" max="50" name="chargeguard_api_down_rate_limit" value="<?php echo esc_attr($api_down_rate_limit); ?>" style="width:70px;padding:4px 8px;border:1px solid #ddd;border-radius:6px;" />
                        <span style="font-size:11px;color:#94a3b8;"><?php esc_html_e( 'unscored orders allowed per IP per 5 minutes while the API is down (Local Checks mode only)', 'chargeguard-woocommerce' ); ?></span>
                    </span>
                </div>

                <div id="cg-apidown-ack-wrap" style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 14px;margin:12px 0;<?php echo $api_down_behavior === 'allow_all' ? '' : 'display:none;'; ?>">
                    <p style="margin:0 0 8px;font-size:12px;color:#991b1b;line-height:1.5;">
                        ⚠️ <?php esc_html_e( '"Allow all orders unscored" means EVERY order is approved with zero fraud screening for as long as the API is unreachable — including a deliberately-triggered outage. Only enable this if you fully understand and accept that risk.', 'chargeguard-woocommerce' ); ?>
                    </p>
                    <label style="font-size:12px;color:#991b1b;display:flex;align-items:center;gap:6px;">
                        <input type="checkbox" name="chargeguard_api_down_allow_all_ack" value="1" <?php checked('1', $api_down_ack); ?> />
                        <?php esc_html_e( 'I understand and accept this risk.', 'chargeguard-woocommerce' ); ?>
                    </label>
                </div>
                <p style="margin:6px 0 0;font-size:11px;color:#94a3b8;">
                    <?php esc_html_e( 'Without the acknowledgment checkbox above, "Allow all orders unscored" is automatically treated as "Local checks" for safety.', 'chargeguard-woocommerce' ); ?>
                </p>

                <?php submit_button('Save Fallback Settings', 'secondary', 'submit', false, ['style' => 'margin-top:14px;']); ?>
            </form>
        </div>

        <!-- Auto-Block Settings -->
        <?php
        $auto_block_enabled  = get_option( 'chargeguard_auto_block', 'no' );
        $block_min_amount    = get_option( 'chargeguard_block_min_amount', 0 );
        $auto_refund_enabled = get_option( 'chargeguard_auto_refund', 'no' );
        ?>
        <div class="cg-card">
            <h3 style="margin:0 0 4px;font-size:15px;">🚫 <?php esc_html_e( 'Auto-Block on Fraud Decision', 'chargeguard-woocommerce' ); ?></h3>
            <p style="margin:0 0 12px;font-size:13px;color:#64748b;">
                <?php esc_html_e( 'Automatically fail an order when ChargeGuard returns a "block" decision from a payment webhook.', 'chargeguard-woocommerce' ); ?>
            </p>
            <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:12px 14px;margin-bottom:16px;font-size:12px;color:#9a3412;line-height:1.5;">
                ⚠️ <strong><?php esc_html_e( 'Important:', 'chargeguard-woocommerce' ); ?></strong>
                <?php esc_html_e( 'Stripe and PayPal webhooks fire after the payment has already been captured. Enabling this will mark the order as "Failed" in WooCommerce, but it will NOT automatically refund the customer — see Auto-Refund below if you also want that.', 'chargeguard-woocommerce' ); ?>
            </div>
            <form method="post" action="options.php">
                <?php settings_fields( 'chargeguard_autoblock_settings' ); ?>
                <div class="cg-info-row">
                    <span class="cg-info-label"><?php esc_html_e( 'Enable Auto-Block', 'chargeguard-woocommerce' ); ?></span>
                    <input type="checkbox" name="chargeguard_auto_block" value="yes" <?php checked( 'yes', $auto_block_enabled ); ?> />
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label"><?php esc_html_e( 'Minimum Order Amount', 'chargeguard-woocommerce' ); ?></span>
                    <input type="number" step="0.01" min="0" name="chargeguard_block_min_amount" value="<?php echo esc_attr( $block_min_amount ); ?>" style="width:100px;padding:4px 8px;border:1px solid #ddd;border-radius:6px;" />
                </div>
                <p style="margin:6px 0 16px;font-size:11px;color:#94a3b8;">
                    <?php esc_html_e( 'Orders below this amount will never be auto-blocked, even on a "block" decision. Set to 0 to apply to all amounts.', 'chargeguard-woocommerce' ); ?>
                </p>

                <hr style="border:none;border-top:1px solid #f0f0f0;margin:16px 0;" />

                <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 14px;margin-bottom:14px;">
                    <p style="margin:0 0 8px;font-size:13px;font-weight:700;color:#991b1b;">
                        🛑 <?php esc_html_e( 'Auto-Refund (Dangerous — moves real money)', 'chargeguard-woocommerce' ); ?>
                    </p>
                    <p style="margin:0 0 10px;font-size:12px;color:#991b1b;line-height:1.5;">
                        <?php esc_html_e( 'When enabled, ChargeGuard will automatically refund the FULL payment on Stripe or PayPal immediately after auto-blocking an order. This action cannot be easily undone. Only enable this if you understand and accept the risk of an automated refund being issued on a false positive.', 'chargeguard-woocommerce' ); ?>
                    </p>
                    <div class="cg-info-row" style="margin:0;">
                        <span class="cg-info-label"><?php esc_html_e( 'Enable Auto-Refund', 'chargeguard-woocommerce' ); ?></span>
                        <input type="checkbox" name="chargeguard_auto_refund" value="yes" <?php checked( 'yes', $auto_refund_enabled ); ?> />
                    </div>
                    <p style="margin:8px 0 0;font-size:11px;color:#991b1b;">
                        <?php esc_html_e( 'Has no effect unless Enable Auto-Block above is also checked.', 'chargeguard-woocommerce' ); ?>
                    </p>
                </div>

                <?php submit_button( __( 'Save Auto-Block Settings', 'chargeguard-woocommerce' ), 'secondary', 'submit', false, [ 'style' => 'margin-top:0;' ] ); ?>
            </form>
        </div>

        

        <!-- Stripe Integration -->
        <?php if ($is_connected): ?>
        <?php
        $st_enabled        = get_option('chargeguard_stripe_enabled', '0');
        $st_secret_key     = get_option('chargeguard_stripe_secret_key', '');
        $st_webhook_secret = get_option('chargeguard_stripe_webhook_secret', '');
        $st_webhook_url    = str_replace( 'http://', 'https://', get_rest_url( null, 'chargeguard/v1/stripe-webhook' ) );
        ?>
        <div class="cg-card" id="cg-stripe-integration">
            <h3 style="margin:0 0 4px;font-size:15px;">💳 Stripe Integration</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Extend ChargeGuard protection to payments made via Stripe.
                Connect your Stripe account to monitor card testing attempts across all payment gateways.
            </p>

            <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
                <div class="cg-status-badge <?php echo $st_enabled === '1' ? 'connected' : 'disconnected'; ?>"
                     style="margin-bottom:0;">
                    <div class="cg-dot <?php echo $st_enabled === '1' ? 'green' : 'gray'; ?>"></div>
                    <?php echo $st_enabled === '1' ? 'Stripe Protection Active' : 'Not Configured'; ?>
                </div>
            </div>

            <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 16px;margin-bottom:20px;">
                <div style="font-size:12px;font-weight:600;color:#475569;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">
                    Your Webhook URL
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <code style="flex:1;font-size:12px;background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:8px 12px;color:#1e293b;word-break:break-all;">
                        <?php echo esc_html($st_webhook_url); ?>
                    </code>
                    <button id="cg-st-copy-url" class="button" title="Copy URL" style="flex-shrink:0;">
                        📋 Copy
                    </button>
                </div>
                <p style="font-size:11px;color:#94a3b8;margin:8px 0 0;">
                    Paste this URL in your <strong>Stripe Dashboard</strong> → Developers → Webhooks → Add endpoint, and select the
                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;">payment_intent.succeeded</code> event.
                </p>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Secret Key</span>
                <input type="password" id="cg-st-secret-key" class="cg-input"
                       value=""
                       placeholder="<?php echo $st_secret_key ? '••••••••••••••••' : 'sk_live_...'; ?>"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    <?php echo $st_secret_key ? 'Leave blank to keep your current key' : 'Found in your Stripe Dashboard → Developers → API keys'; ?>
                </span>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Webhook Signing Secret</span>
                <input type="password" id="cg-st-webhook-secret" class="cg-input"
                       value=""
                       placeholder="<?php echo $st_webhook_secret ? '••••••••••••••••' : 'whsec_...'; ?>"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    <?php echo $st_webhook_secret ? 'Leave blank to keep your current secret' : 'Shown once after creating the endpoint in your Stripe Dashboard'; ?>
                </span>
            </div>

            <div class="cg-info-row">
                <span class="cg-info-label">Enable Protection</span>
                <div class="cg-toggle-wrap">
                    <input type="checkbox" class="cg-toggle" id="cg-st-enabled" <?php checked('1', $st_enabled); ?> />
                    <label for="cg-st-enabled" style="font-size:12px;color:#64748b;">Active</label>
                </div>
            </div>

            <div style="display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap;">
                <button id="cg-st-save" class="cg-btn cg-btn-primary" style="margin:0;">
                    💾 Save Stripe Settings
                </button>
                <button id="cg-st-test" class="cg-btn" style="margin:0;background:#fff;color:#f97316;border:1px solid #f97316;">
                    🔗 Test Connection
                </button>
            </div>
            <div id="cg-st-message" class="cg-message" style="margin-top:10px;"></div>
        </div>
        <?php endif; ?>

        <!-- PayPal Integration -->
        <?php if ($is_connected && $merchant_is_pro_or_above): ?>
        <?php
        $pp_enabled    = get_option('chargeguard_paypal_enabled', '0');
        $pp_client_id  = get_option('chargeguard_paypal_client_id', '');
        $pp_webhook_id = get_option('chargeguard_paypal_webhook_id', '');
        $pp_mode       = get_option('chargeguard_paypal_mode', 'sandbox');
        $pp_webhook_url = str_replace( 'http://', 'https://', get_rest_url( null, 'chargeguard/v1/paypal-webhook' ) );
        ?>
        <div class="cg-card" id="cg-paypal-integration">
            <h3 style="margin:0 0 4px;font-size:15px;">🅿️ PayPal Integration</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Extend ChargeGuard protection to payments made via PayPal.
                Connect your PayPal app to monitor card testing attempts across all payment gateways.
            </p>

            <!-- Status Badge -->
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
                <div class="cg-status-badge <?php echo $pp_enabled === '1' ? 'connected' : 'disconnected'; ?>"
                     style="margin-bottom:0;">
                    <div class="cg-dot <?php echo $pp_enabled === '1' ? 'green' : 'gray'; ?>"></div>
                    <?php echo $pp_enabled === '1' ? 'PayPal Protection Active' : 'Not Configured'; ?>
                </div>
                <?php if ($pp_enabled === '1'): ?>
                <span style="font-size:11px;color:#94a3b8;background:#f8fafc;padding:3px 8px;border-radius:4px;border:1px solid #e2e8f0;">
                    <?php echo $pp_mode === 'live' ? '🟢 Live' : '🟡 Sandbox'; ?>
                </span>
                <?php endif; ?>
            </div>

            <!-- Webhook URL (للتاجر لنسخه في PayPal Dashboard) -->
            <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 16px;margin-bottom:20px;">
                <div style="font-size:12px;font-weight:600;color:#475569;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">
                    Your Webhook URL
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <code style="flex:1;font-size:12px;background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:8px 12px;color:#1e293b;word-break:break-all;">
                        <?php echo esc_html($pp_webhook_url); ?>
                    </code>
                    <button id="cg-pp-copy-url" class="button" title="Copy URL"
                            style="flex-shrink:0;">
                        📋 Copy
                    </button>
                </div>
                <p style="font-size:11px;color:#94a3b8;margin:8px 0 0;">
                    Paste this URL in your <strong>PayPal Developer Dashboard</strong> → Apps & Credentials → Webhooks.
                </p>
            </div>

            <!-- Inline Setup Guide -->
            <details id="cg-pp-guide" style="margin-bottom:20px;">
                <summary style="cursor:pointer;font-size:13px;font-weight:600;color:#f97316;
                                list-style:none;display:flex;align-items:center;gap:6px;
                                padding:10px 14px;background:#fff7ed;border:1px solid #fed7aa;
                                border-radius:8px;user-select:none;">
                    <span id="cg-pp-guide-arrow" style="transition:transform 0.2s;display:inline-block;">▶</span>
                    📖 How to get your PayPal credentials <span style="font-weight:400;color:#94a3b8;font-size:12px;margin-left:4px;">3 steps · ~2 min</span>
                </summary>
                <div style="border:1px solid #fed7aa;border-top:none;border-radius:0 0 8px 8px;
                            padding:16px 18px;background:#fffbf7;">
                    <div style="display:flex;flex-direction:column;gap:14px;">

                        <!-- Step 1 -->
                        <div style="display:flex;gap:12px;align-items:flex-start;">
                            <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;
                                        background:#f97316;color:#fff;font-size:12px;font-weight:700;
                                        display:flex;align-items:center;justify-content:center;">1</div>
                            <div>
                                <div style="font-size:13px;font-weight:600;color:#1e293b;margin-bottom:3px;">
                                    Create a PayPal App
                                </div>
                                <div style="font-size:12px;color:#64748b;line-height:1.5;">
                                    Go to
                                    <a href="https://developer.paypal.com/dashboard/applications" target="_blank"
                                       style="color:#f97316;text-decoration:none;font-weight:600;">
                                        PayPal Developer Dashboard ↗
                                    </a>
                                    → <strong>Apps & Credentials</strong> → <strong>Create App</strong>.
                                    Choose <em>Merchant</em> as the app type.
                                </div>
                            </div>
                        </div>

                        <!-- Step 2 -->
                        <div style="display:flex;gap:12px;align-items:flex-start;">
                            <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;
                                        background:#f97316;color:#fff;font-size:12px;font-weight:700;
                                        display:flex;align-items:center;justify-content:center;">2</div>
                            <div>
                                <div style="font-size:13px;font-weight:600;color:#1e293b;margin-bottom:3px;">
                                    Copy your Client ID & Secret
                                </div>
                                <div style="font-size:12px;color:#64748b;line-height:1.5;">
                                    Inside your app page, copy the <strong>Client ID</strong> and
                                    <strong>Secret</strong> from the credentials section.
                                    Use <em>Sandbox</em> for testing, <em>Live</em> for production.
                                </div>
                            </div>
                        </div>

                        <!-- Step 3 -->
                        <div style="display:flex;gap:12px;align-items:flex-start;">
                            <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;
                                        background:#f97316;color:#fff;font-size:12px;font-weight:700;
                                        display:flex;align-items:center;justify-content:center;">3</div>
                            <div>
                                <div style="font-size:13px;font-weight:600;color:#1e293b;margin-bottom:3px;">
                                    Add a Webhook & get the Webhook ID
                                </div>
                                <div style="font-size:12px;color:#64748b;line-height:1.5;">
                                    In the same app page → <strong>Webhooks</strong> → <strong>Add Webhook</strong>.
                                    Paste your Webhook URL above, select these events:
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        PAYMENT.CAPTURE.COMPLETED
                                    </code>
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        PAYMENT.CAPTURE.DENIED
                                    </code>
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        CHECKOUT.ORDER.APPROVED
                                    </code>
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        RISK.DISPUTE.CREATED
                                    </code>.
                                    After saving, copy the <strong>Webhook ID</strong> shown on the webhook page.
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
            </details>

            <!-- Fields -->
            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Environment</span>
                <div style="display:flex;gap:0;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
                    <button class="cg-pp-mode-btn <?php echo $pp_mode === 'sandbox' ? 'active' : ''; ?>"
                            data-mode="sandbox"
                            style="padding:7px 16px;border:none;cursor:pointer;font-size:13px;font-weight:600;
                                   background:<?php echo $pp_mode === 'sandbox' ? '#f0fdf4' : '#fff'; ?>;
                                   color:<?php echo $pp_mode === 'sandbox' ? '#16a34a' : '#999'; ?>;">
                        Sandbox
                    </button>
                    <button class="cg-pp-mode-btn <?php echo $pp_mode === 'live' ? 'active' : ''; ?>"
                            data-mode="live"
                            style="padding:7px 16px;border:none;cursor:pointer;font-size:13px;font-weight:600;
                                   background:<?php echo $pp_mode === 'live' ? '#f0fdf4' : '#fff'; ?>;
                                   color:<?php echo $pp_mode === 'live' ? '#16a34a' : '#999'; ?>;
                                   border-left:1px solid #ddd;">
                        Live
                    </button>
                </div>
                <input type="hidden" id="cg-pp-mode" value="<?php echo esc_attr($pp_mode); ?>" />
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Client ID</span>
                <input type="text" id="cg-pp-client-id" class="cg-input"
                       value="<?php echo esc_attr($pp_client_id); ?>"
                       placeholder="AYour_PayPal_Client_ID"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    Found in your PayPal App → Credentials
                </span>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Client Secret</span>
                <input type="password" id="cg-pp-client-secret" class="cg-input"
                       value=""
                       placeholder="<?php echo $pp_client_id ? '••••••••••••••••' : 'EYour_PayPal_Client_Secret'; ?>"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    <?php echo $pp_client_id ? 'Leave blank to keep your current secret' : 'Found in your PayPal App → Credentials'; ?>
                </span>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Webhook ID</span>
                <input type="text" id="cg-pp-webhook-id" class="cg-input"
                       value="<?php echo esc_attr($pp_webhook_id); ?>"
                       placeholder="Get this from PayPal Developer Dashboard"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    Found on your Webhook page after saving it in PayPal
                </span>
            </div>

            <div class="cg-info-row">
                <span class="cg-info-label">Enable Protection</span>
                <div class="cg-toggle-wrap">
                    <input type="checkbox" class="cg-toggle" id="cg-pp-enabled"
                           <?php checked('1', $pp_enabled); ?> />
                    <label for="cg-pp-enabled" style="font-size:12px;color:#64748b;">Active</label>
                </div>
            </div>

            <div style="display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap;">
                <button id="cg-pp-save" class="cg-btn cg-btn-primary" style="margin:0;">
                    💾 Save PayPal Settings
                </button>
                <button id="cg-pp-test" class="cg-btn"
                        style="margin:0;background:#fff;color:#f97316;border:1px solid #f97316;">
                    🔗 Test Connection
                </button>
            </div>
            <div id="cg-pp-message" class="cg-message" style="margin-top:10px;"></div>
        </div>
        <?php elseif ($is_connected): ?>
        <div class="cg-card" id="cg-paypal-integration-locked">
            <h3 style="margin:0 0 4px;font-size:15px;">🅿️ PayPal Integration</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Extend ChargeGuard protection to payments made via PayPal.
                Connect your PayPal app to monitor card testing attempts across all payment gateways.
            </p>
            <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:20px;text-align:center;">
                <div style="font-size:28px;margin-bottom:8px;">🔒</div>
                <p style="margin:0 0 14px;font-size:13px;color:#9a3412;">
                    <?php esc_html_e( 'Real-time PayPal suspicious-transaction alerts are a Pro plan feature. Upgrade to monitor PayPal transactions alongside your card payments.', 'chargeguard-woocommerce' ); ?>
                </p>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=chargeguard-settings&upgrade=pro' ) ); ?>" class="cg-btn cg-btn-primary" style="display:inline-block;text-decoration:none;">
                    ⬆️ <?php esc_html_e( 'Upgrade to Pro', 'chargeguard-woocommerce' ); ?>
                </a>
            </div>
        </div>
        <?php endif; ?>

        <!-- Managed Stores (Agency full CRUD, or read-only cleanup mode for downgraded ex-Agency tenants) -->
        <?php if ($show_managed_stores_card): ?>
        <div class="cg-card" id="cg-managed-stores" data-mode="<?php echo $merchant_is_agency ? 'full' : 'cleanup'; ?>">
            <h3 style="margin:0 0 4px;font-size:15px;">🏬 Managed Stores</h3>
            <?php if ($merchant_is_agency): ?>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                <?php esc_html_e( 'Add each client store domain you manage under this Agency account. ChargeGuard only accepts API requests from domains registered here.', 'chargeguard-woocommerce' ); ?>
            </p>

            <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start;">
                <input type="text" id="cg-store-url" class="cg-input"
                       placeholder="e.g. clienta-store.com"
                       style="flex:1;min-width:200px;margin:0;" />
                <input type="text" id="cg-store-label" class="cg-input"
                       placeholder="Label (optional) — e.g. Client A"
                       style="flex:1;min-width:160px;margin:0;" />
                <button id="cg-store-add" class="cg-btn cg-btn-primary" style="margin:0;white-space:nowrap;">
                    + Add Store
                </button>
            </div>
            <?php else: ?>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                <?php esc_html_e( 'These stores are no longer active because your Agency plan has ended. You can remove any store you no longer need below. Renew your Agency plan to add new stores or reactivate an existing one.', 'chargeguard-woocommerce' ); ?>
            </p>
            <?php endif; ?>
            <div id="cg-store-message" class="cg-message"></div>
            <div id="cg-store-table-wrap">
                <p style="color:#999;font-size:13px;">Loading…</p>
            </div>
        </div>
        <?php endif; ?>

        <!-- Notification Channels -->
        <?php if ($is_connected && $merchant_is_pro_or_above): ?>
        <div class="cg-card" id="cg-notification-channels">
            <h3 style="margin:0 0 4px;font-size:15px;">📢 Notification Channels</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Receive attack alerts in Slack or Discord alongside email notifications.
            </p>

            <div class="cg-info-row">
                <span class="cg-info-label">Email Notifications</span>
                <span class="cg-info-value" style="color:#16a34a;">✅ Always Active</span>
            </div>

            <div style="border-top:1px solid #f0f0f0;padding-top:14px;margin-top:4px;">
                <label style="font-size:13px;font-weight:600;color:#333;">Webhook Platform</label>
                <div style="display:flex;gap:0;margin:10px 0 16px;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
                    <button class="cg-webhook-tab cg-webhook-active" data-type="slack"
                        style="flex:1;padding:10px;border:none;background:#f0fdf4;cursor:pointer;font-size:13px;font-weight:600;color:#16a34a;">
                        Slack
                    </button>
                    <button class="cg-webhook-tab" data-type="discord"
                        style="flex:1;padding:10px;border:none;background:#fff;cursor:pointer;font-size:13px;font-weight:600;color:#999;border-left:1px solid #ddd;">
                        Discord
                    </button>
                    <button class="cg-webhook-tab" data-type="custom"
                        style="flex:1;padding:10px;border:none;background:#fff;cursor:pointer;font-size:13px;font-weight:600;color:#999;border-left:1px solid #ddd;">
                        Custom
                    </button>
                </div>
                <p id="cg-webhook-guide" style="font-size:12px;color:#94a3b8;margin:0 0 12px;">
                    Create an <strong>Incoming Webhook</strong> in Slack → paste the URL below.
                </p>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:100px;">Webhook URL</span>
                <input type="url" id="cg-webhook-url" class="cg-input"
                       placeholder="https://hooks.slack.com/services/..."
                       style="flex:1;min-width:220px;margin:0;" />
            </div>

            <div style="display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap;">
                <button id="cg-webhook-save" class="cg-btn cg-btn-primary" style="margin:0;">
                    💾 Save Webhook
                </button>
                <button id="cg-webhook-test" class="cg-btn" style="margin:0;background:#fff;color:#f97316;border:1px solid #f97316;">
                    📤 Send Test Notification
                </button>
                <div id="cg-webhook-status" style="font-size:12px;color:#94a3b8;display:flex;align-items:center;gap:6px;">
                    <span id="cg-webhook-status-dot" style="display:none;width:8px;height:8px;border-radius:50%;"></span>
                    <span id="cg-webhook-status-text">Not configured</span>
                </div>
            </div>
            <div id="cg-webhook-message" class="cg-message" style="margin-top:10px;"></div>
        </div>
        <?php elseif ($is_connected): ?>
        <div class="cg-card" id="cg-notification-channels-locked">
            <h3 style="margin:0 0 4px;font-size:15px;">📢 Notification Channels</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Receive attack alerts in Slack or Discord alongside email notifications.
            </p>
            <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:20px;text-align:center;">
                <div style="font-size:28px;margin-bottom:8px;">🔒</div>
                <p style="margin:0 0 14px;font-size:13px;color:#9a3412;">
                    <?php esc_html_e( 'Slack/Discord webhook alerts are a Pro plan feature. Upgrade to receive real-time attack notifications in your team channels.', 'chargeguard-woocommerce' ); ?>
                </p>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=chargeguard-settings&upgrade=pro' ) ); ?>" class="cg-btn cg-btn-primary" style="display:inline-block;text-decoration:none;">
                    ⬆️ <?php esc_html_e( 'Upgrade to Pro', 'chargeguard-woocommerce' ); ?>
                </a>
            </div>
        </div>
        <?php endif; ?>

        </div>

        <?php
    }
}