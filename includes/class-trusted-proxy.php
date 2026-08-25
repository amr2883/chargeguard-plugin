<?php
defined('ABSPATH') || exit;

/**
 * Resolves the visitor IP using verified-hop proxy trust, replacing the
 * old "toggle on = trust any X-Forwarded-For" model.
 *
 * Trust model:
 *   - Cloudflare: CF-Connecting-IP is honored ONLY when REMOTE_ADDR (the
 *     actual TCP peer) falls inside Cloudflare's published IP ranges.
 *     This is what makes the header unspoofable in practice — Cloudflare
 *     itself overwrites any client-supplied CF-Connecting-IP, but that
 *     guarantee is worthless if an attacker can reach the origin
 *     directly and bypass Cloudflare entirely.
 *   - Generic reverse proxy (Nginx/ALB/etc.): X-Forwarded-For is honored
 *     only when REMOTE_ADDR is inside the merchant-configured trusted
 *     proxy CIDR list.
 *   - Neither condition met -> REMOTE_ADDR, always.
 */
class ChargeGuard_Trusted_Proxy {

    const CF_RANGES_OPTION       = 'chargeguard_cf_ranges_cache';
    const CF_RANGES_FETCHED_AT   = 'chargeguard_cf_ranges_fetched_at';
    const CF_RANGES_TTL          = DAY_IN_SECONDS;
    const CUSTOM_PROXY_CIDR_OPT  = 'chargeguard_trusted_proxy_cidrs'; // merchant-entered, newline-separated
    const PROXY_MODE_OPTION      = 'chargeguard_proxy_trust_mode';    // 'off' | 'cloudflare' | 'custom' | 'both'

    /** Hardcoded fallback in case the daily refresh has never run or is stale beyond TTL+grace. */
    private static function fallback_cf_ranges() {
        return [
            '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
            '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
            '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
            '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
            // IPv6
            '2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32',
            '2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32',
        ];
    }

    /**
     * Cloudflare ranges, cached in an option and refreshed via WP-Cron
     * daily — NEVER fetched inline on the checkout request path. If the
     * cron hasn't run yet (fresh install) or the cache is empty, fall
     * back to the hardcoded list above rather than fail open.
     */
    public static function get_cf_ranges() {
        $cached = get_option(self::CF_RANGES_OPTION, []);
        if (is_array($cached) && !empty($cached)) {
            return $cached;
        }
        return self::fallback_cf_ranges();
    }

    /**
     * WP-Cron callback (registered in main plugin file on
     * chargeguard_refresh_cf_ranges, scheduled daily). Network call
     * happens here — off the request path entirely.
     *
     * As of the backend-owned-source-of-truth fix, this no longer hits
     * cloudflare.com directly. It polls the backend's authenticated
     * GET /risk/cloudflare-ranges endpoint via
     * ChargeGuard_API_Client::get_cloudflare_ranges() (backed by
     * src/lib/cloudflareRanges.js on the backend, which itself owns the
     * daily Cloudflare fetch). If the backend is unreachable, or its
     * response is empty/malformed, the previously-cached option (or,
     * failing that, fallback_cf_ranges()) is left untouched — no
     * regression versus the old direct-fetch behavior.
     */
    public static function refresh_cf_ranges() {
        $api_client = new ChargeGuard_API_Client();
        $result     = $api_client->get_cloudflare_ranges();

        if (is_wp_error($result)) {
            error_log('[ChargeGuard] Cloudflare IP range refresh from backend failed — keeping previous cached list (or hardcoded fallback): ' . $result->get_error_message());
            return;
        }

        $ranges = (is_array($result) && isset($result['ranges']) && is_array($result['ranges']))
            ? $result['ranges']
            : null;

        if ($ranges === null || empty($ranges)) {
            error_log('[ChargeGuard] Cloudflare IP range refresh from backend returned no ranges — keeping previous cached list (or hardcoded fallback).');
            return;
        }

        // Defensive validation: only accept well-formed CIDR strings — the
        // same shape the old direct-from-Cloudflare parsing produced.
        // Protects ip_in_any_cidr() below from a malformed backend
        // response, since inet_pton()/explode() there assume clean input.
        $clean_ranges = [];
        foreach ($ranges as $line) {
            if (is_string($line) && strpos($line, '/') !== false) {
                $clean_ranges[] = trim($line);
            }
        }

        if (empty($clean_ranges)) {
            error_log('[ChargeGuard] Cloudflare IP range refresh from backend returned no valid CIDR entries — keeping previous cached list (or hardcoded fallback).');
            return;
        }

        update_option(self::CF_RANGES_OPTION, $clean_ranges, false);
        update_option(self::CF_RANGES_FETCHED_AT, time(), false);
    }

    /** O(1)-ish bounded CIDR match — no regex, cheap integer/bit compare. */
    public static function ip_in_any_cidr($ip, array $cidrs) {
        foreach ($cidrs as $cidr) {
            if (self::ip_in_cidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    private static function ip_in_cidr($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return false;
        }
        [$subnet, $mask] = explode('/', $cidr, 2);
        $mask = (int) $mask;

        $ip_bin     = @inet_pton($ip);
        $subnet_bin = @inet_pton($subnet);
        if ($ip_bin === false || $subnet_bin === false || strlen($ip_bin) !== strlen($subnet_bin)) {
            return false; // family mismatch (v4 vs v6) — never matches
        }

        $bytes = intdiv($mask, 8);
        $bits  = $mask % 8;

        if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($subnet_bin, 0, $bytes)) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask_byte = 0xFF << (8 - $bits) & 0xFF;
        return (ord($ip_bin[$bytes]) & $mask_byte) === (ord($subnet_bin[$bytes]) & $mask_byte);
    }

    /**
     * Merchant-configured custom proxy CIDR list (Nginx/ALB/etc.),
     * parsed and validated. Invalid lines are dropped silently rather
     * than erroring the whole list — a mistyped line shouldn't take
     * down IP resolution for every other correctly-entered range.
     */
    public static function get_custom_proxy_cidrs() {
        $raw = get_option(self::CUSTOM_PROXY_CIDR_OPT, '');
        $out = [];
        foreach (preg_split('/\R/', (string) $raw) as $line) {
            $line = trim($line);
            if ($line === '') continue;
            if (strpos($line, '/') === false) {
                // bare IP — treat as /32 or /128
                $line .= (strpos($line, ':') !== false) ? '/128' : '/32';
            }
            [$addr] = explode('/', $line, 2);
            if (filter_var($addr, FILTER_VALIDATE_IP)) {
                $out[] = $line;
            }
        }
        return $out;
    }

    /**
     * Does the *connection itself* (REMOTE_ADDR) look like it's arriving
     * through Cloudflare or a generic reverse proxy, regardless of
     * current settings? Used purely for the admin-notice nudge — never
     * for a trust decision.
     */
    public static function looks_like_behind_proxy() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !empty($_SERVER['HTTP_CF_RAY'])) {
            return 'cloudflare';
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) || !empty($_SERVER['HTTP_X_REAL_IP'])) {
            return 'generic';
        }
        return false;
    }

    /**
     * Resolves the real client IP from a raw X-Forwarded-For header value.
     * Called ONLY after REMOTE_ADDR has already been verified to sit
     * inside a trusted proxy's CIDR range (see get_client_ip() in
     * class-dynamic-firewall.php) — never on its own.
     *
     * SECURITY: deliberately does NOT take the first (leftmost) entry
     * the way WC_Geolocation::get_ip_address() does. A client can freely
     * send "X-Forwarded-For: <fake>, <real>", and a proxy that appends
     * rather than replaces the header (the common nginx
     * $proxy_add_x_forwarded_for behavior, and the default for most
     * reverse proxies / load balancers) leaves that fake IP untouched
     * at the front of the chain.
     *
     * Instead this takes the LAST (rightmost) syntactically valid IP —
     * the entry our own trusted proxy hop is responsible for appending,
     * and therefore the only one we can actually vouch for. This is a
     * single-trusted-hop model; it does not attempt to walk a
     * multi-proxy trusted chain.
     */
    public static function resolve_ip_from_forwarded_header($header_value) {
        $parts = explode(',', (string) $header_value);
        for ($i = count($parts) - 1; $i >= 0; $i--) {
            $candidate = trim($parts[$i]);
            if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }
        return '';
    }
}