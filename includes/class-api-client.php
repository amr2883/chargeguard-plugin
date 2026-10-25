<?php
/**
 * ChargeGuard API Client
 *
 * Handles authenticated communication with the ChargeGuard backend.
 *
 * @package ChargeGuard_WooCommerce
 */

if (!defined('CHARGEGUARD_CIRCUIT_FAILURE_THRESHOLD')) {
    define('CHARGEGUARD_CIRCUIT_FAILURE_THRESHOLD', 3); // consecutive failures before opening
}
if (!defined('CHARGEGUARD_CIRCUIT_OPEN_SECONDS')) {
    define('CHARGEGUARD_CIRCUIT_OPEN_SECONDS', 60); // cool-down before the next call is attempted
}

class ChargeGuard_API_Client {

    private $api_key;
    
    private $webhook_secret;
    private $base_url = 'https://chargeguard-api.onrender.com/api';

    /** Transient key holding the consecutive-failure count. */
    const CIRCUIT_FAILURE_TRANSIENT = 'chargeguard_circuit_failures';

    /** Transient key marking the circuit as open (calls skipped) while it exists. */
    const CIRCUIT_OPEN_TRANSIENT = 'chargeguard_circuit_open';

    /** Persistent option used to show merchants a degraded-protection notice. */
    const CIRCUIT_STATUS_OPTION = 'chargeguard_circuit_status';

    public function __construct() {
        $this->api_key = function_exists('chargeguard_get_secret_option')
            ? chargeguard_get_secret_option('chargeguard_api_key')
            : get_option('chargeguard_api_key');

        $this->webhook_secret = function_exists('chargeguard_get_secret_option')
            ? chargeguard_get_secret_option('chargeguard_webhook_secret')
            : get_option('chargeguard_webhook_secret');

        add_action('admin_notices', [$this, 'maybe_show_circuit_notice']);
    }

    /**
     * الحصول على مفتاح API الحالي.
     *
     * @return string|null
     */
    public function get_api_key() {
        return $this->api_key;
    }

    /**
     * Whether the circuit breaker is currently open (skip the API call and
     * fail open).
     *
     * @return bool
     */
    private function is_circuit_open() {
        return (bool) get_transient(self::CIRCUIT_OPEN_TRANSIENT);
    }

    /**
     * Record a failed call. Opens the circuit once the configured
     * consecutive-failure threshold is reached.
     */
    private function record_failure() {
        // NOTE (known low-severity race, acceptable for launch): this
        // read-increment-write is not atomic. Under high-concurrency
        // traffic (e.g. a card-testing burst or a backend outage hitting
        // many requests at once), two overlapping requests can both read
        // the same $failures value and each write back the same
        // incremented count, silently losing an increment. Worst case,
        // the circuit breaker opens one request later than it ideally
        // would — it still opens, just with a possible one-request delay.
        // This is self-correcting and does not require an immediate fix.
        //
        // Future improvement path: replace this with an atomic
        // wp_cache_increment() call once a persistent object cache
        // (Redis or Memcached) is available/detected — wp_cache_increment()
        // performs the increment atomically in the cache backend itself,
        // eliminating this race entirely. Not implemented now because it
        // requires a runtime fallback for installs without a persistent
        // object cache (see wp_using_ext_object_cache()), which is
        // unnecessary complexity for a low-severity, self-correcting issue.
        $failures = (int) get_transient(self::CIRCUIT_FAILURE_TRANSIENT);
        $failures++;
        set_transient(self::CIRCUIT_FAILURE_TRANSIENT, $failures, CHARGEGUARD_CIRCUIT_OPEN_SECONDS * 2);

        $threshold = (int) apply_filters('chargeguard_circuit_failure_threshold', CHARGEGUARD_CIRCUIT_FAILURE_THRESHOLD);

        if ($failures >= $threshold) {
            $open_seconds = (int) apply_filters('chargeguard_circuit_open_seconds', CHARGEGUARD_CIRCUIT_OPEN_SECONDS);
            set_transient(self::CIRCUIT_OPEN_TRANSIENT, time(), $open_seconds);

            update_option(self::CIRCUIT_STATUS_OPTION, [
                'status'     => 'open',
                'opened_at'  => time(),
                'reopens_in' => $open_seconds,
            ], false);

            error_log('ChargeGuard: circuit breaker opened after ' . $failures . ' consecutive failures.');
        }
    }

    /**
     * Record a successful call. Resets the failure counter and closes the
     * circuit (and clears the merchant-visible flag) if it was open.
     */
    private function record_success() {
        delete_transient(self::CIRCUIT_FAILURE_TRANSIENT);

        if (get_transient(self::CIRCUIT_OPEN_TRANSIENT)) {
            delete_transient(self::CIRCUIT_OPEN_TRANSIENT);
            error_log('ChargeGuard: circuit breaker closed — API reachable again.');
        }

        update_option(self::CIRCUIT_STATUS_OPTION, [
            'status'     => 'closed',
            'opened_at'  => null,
            'reopens_in' => 0,
        ], false);
    }

    /**
     * POST with a single immediate (non-blocking) retry on network failure
     * or 5xx, guarded by the circuit breaker. Replaces the previous
     * sleep()-based retry, which held the PHP-FPM worker for seconds.
     *
     * @param string $url
     * @param array  $args wp_remote_post() args.
     * @return array|WP_Error wp_remote_post()-style response, or a
     *                        'chargeguard_circuit_open' WP_Error if the
     *                        breaker is currently open.
     */
    private function request_with_breaker($url, $method, $raw_body, $timeout) {
        if ($this->is_circuit_open()) {
            // NOTE: this error no longer implies "fail open" by itself.
            // What happens next is decided by the caller — see
            // ChargeGuard_Dynamic_Firewall::resolve_api_unavailable_decision()
            // in class-dynamic-firewall.php, which applies the merchant's
            // configured fallback behavior (block-all / local-checks /
            // allow-all) instead of unconditionally approving.
            return new WP_Error(
                'chargeguard_circuit_open',
                'ChargeGuard API circuit breaker is open — skipping call.'
            );
        }

        // request_id بيتولّد مرة واحدة بس هنا، للنداء المنطقي كله (المحاولة
        // الأولى + أي retry). لازم يفضل ثابت عبر كل المحاولات الفعلية —
        // شوف الشرح في generate_hmac() فوق ليه ده أساسي لمنع الـ backend من
        // تنفيذ نفس العملية مرتين أو رفض retry شرعي بالغلط.
        $request_id = wp_generate_uuid4();

        $attempt = function () use ($url, $method, $raw_body, $timeout, $request_id) {
            $headers = $this->build_signed_headers($raw_body, $request_id, $method, $url);
            return wp_remote_request($url, [
                'method'  => $method,
                'headers' => $headers,
                'body'    => $raw_body,
                'timeout' => $timeout,
            ]);
        };

        $response = $attempt();

        // Single immediate retry (no sleep) on network failure or 5xx.
        // نفس $request_id، لكن timestamp/signature جداد تمامًا للمحاولة دي.
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) >= 500) {
            $response = $attempt();
        }

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) >= 500) {
            $this->record_failure();
        } else {
            $this->record_success();
        }

        return $response;
    }

    /**
     * إرسال بيانات enrich إلى ChargeGuard.
     *
     * @param array $data يحتوي على orderId, bin, cardBrand, cardCountry, funding, issuer.
     * @return array|WP_Error نتيجة الاستدعاء.
     */
    public function send_enrich($data) {
        $endpoint = '/risk/enrich';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode($data);

        $response = $this->request_with_breaker($url, 'POST', $body, 5);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }

    /**
     * Fetch the backend's cached Cloudflare IP ranges (GET
     * /risk/cloudflare-ranges). The backend is now the single source of
     * truth for Cloudflare's published ranges — see
     * src/lib/cloudflareRanges.js and routes/risk.js on the backend side.
     * Called from ChargeGuard_Trusted_Proxy::refresh_cf_ranges() instead
     * of hitting cloudflare.com directly.
     *
     * @return array|WP_Error Decoded body (['ranges' => [...]]), or WP_Error.
     */
    public function get_cloudflare_ranges() {
        $endpoint = '/risk/cloudflare-ranges';
        $url      = $this->base_url . $endpoint;

        $response = $this->request_with_breaker($url, 'GET', '', 10);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        }
        return new WP_Error('api_error', $body['error'] ?? 'Failed to fetch Cloudflare ranges.');
    }

    /**
     * فحص بصمة جهاز عبر ChargeGuard API.
     *
     * @param string $fingerprint بصمة الجهاز.
     * @return array|WP_Error
     */
    public function check_device($fingerprint) {
        $endpoint = '/risk/check-device';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode(['fingerprint' => $fingerprint]);

        $response = $this->request_with_breaker($url, 'POST', $body, 3);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }

    /**
     * Report a locally-blocked visitor (e.g. plugin device blacklist) to
     * the backend's dashboard/reporting endpoint. Fire-and-forget,
     * non-blocking, with errors logged only — a failure here must never
     * affect the visitor, since the block has already been enforced
     * client-side by the time this is called. Mirrors reconcile_order()'s
     * fire-and-forget pattern.
     *
     * @param array $data 'reason' is required (e.g. 'blacklist'); optional
     *                    keys: cardBin, cardType, ipHash, deviceFingerprint,
     *                    amountAttempted, riskScore.
     * @return void
     */
    public function send_blocked_attempt($data) {
        if (empty($data['reason'])) {
            return;
        }

        $endpoint = '/risk/blocked-attempt';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode($data);
        $headers  = $this->build_signed_headers($body, wp_generate_uuid4(), 'POST', $url);

        wp_remote_post($url, [
            'method'   => 'POST',
            'blocking' => false,
            'timeout'  => 3,
            'headers'  => $headers,
            'body'     => $body,
        ]);
    }

    /**
     * Send feedback on a previous evaluation to the ChargeGuard backend.
     *
     * @param string $order_id The WooCommerce order ID.
     * @param bool   $is_fraud Whether the order was fraudulent.
     * @return array|WP_Error Result from the API.
     */
    public function send_feedback($order_id, $is_fraud) {
        $endpoint = '/risk/feedback';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'orderId' => (string) $order_id,
            'isFraud' => (bool) $is_fraud,
        ]);

        $response = $this->request_with_breaker($url, 'POST', $body, 5);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }

    /**
     * Fetch whitelist entries for the connected tenant.
     *
     * @return array|WP_Error Decoded response body, or WP_Error on failure.
     */
    public function whitelist_get() {
        $endpoint = '/risk/whitelist';
        $url      = $this->base_url . $endpoint;

        // Content-Type بيتضاف تلقائيًا جوه build_signed_headers() دلوقتي —
        // مفيش حاجة تفوّتها تاني حتى لو GET من غير body (زي ما كان بيحصل
        // قبل كده في stores_get/webhook_status/geo_overrides_get).
        $response = $this->request_with_breaker($url, 'GET', '', 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        }
        return new WP_Error('api_error', $body['error'] ?? 'Failed to fetch whitelist.');
    }

    /**
     * Add an entry to the whitelist.
     *
     * @param string $type   EMAIL|IP|BIN
     * @param string $value
     * @param string $reason Optional note.
     * @return array|WP_Error
     */
    public function whitelist_add($type, $value, $reason = '') {
        $endpoint = '/risk/whitelist';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'type'      => $type,
            'value'     => $value,
            'reason'    => $reason ?: null,
            'createdBy' => get_option('chargeguard_connected_email'),
        ]);

        $response = $this->request_with_breaker($url, 'POST', $body, 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body_decoded;
        }
        if ($code === 409) {
            return new WP_Error('api_conflict', 'This entry already exists in the safe list.');
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to add entry.');
    }

    /**
     * Delete a whitelist entry by ID.
     *
     * @param string $id
     * @return true|WP_Error
     */
    public function whitelist_delete($id) {
        $endpoint = '/risk/whitelist/' . rawurlencode($id);
        $url      = $this->base_url . $endpoint;

        $response = $this->request_with_breaker($url, 'DELETE', '', 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 200 && $code < 300) {
            return true;
        }
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to delete entry.');
    }

    /**
     * Fetch blacklist entries for the connected tenant.
     *
     * @return array|WP_Error
     */
    public function blacklist_get() {
        $endpoint = '/risk/blacklist';
        $url      = $this->base_url . $endpoint;

        $response = $this->request_with_breaker($url, 'GET', '', 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        }
        return new WP_Error('api_error', $body['error'] ?? 'Failed to fetch blacklist.');
    }

    /**
     * Add an entry to the blacklist.
     *
     * @param string $type   EMAIL|IP|DEVICE_FINGERPRINT
     * @param string $value
     * @param string $reason Optional note.
     * @return array|WP_Error
     */
    public function blacklist_add($type, $value, $reason = '') {
        $endpoint = '/risk/blacklist';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'type'      => $type,
            'value'     => $value,
            'reason'    => $reason ?: null,
            'createdBy' => get_option('chargeguard_connected_email'),
        ]);

        $response = $this->request_with_breaker($url, 'POST', $body, 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body_decoded;
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to add entry.');
    }

    /**
     * Delete a blacklist entry by ID.
     *
     * @param string $id
     * @return true|WP_Error
     */
    public function blacklist_delete($id) {
        $endpoint = '/risk/blacklist/' . rawurlencode($id);
        $url      = $this->base_url . $endpoint;

        $response = $this->request_with_breaker($url, 'DELETE', '', 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 200 && $code < 300) {
            return true;
        }
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to delete entry.');
    }

    /**
     * Fetch all Store rows (active and inactive) for the connected
     * Agency tenant.
     *
     * @return array|WP_Error
     */
    public function stores_get() {
        $endpoint = '/stores';
        $url      = $this->base_url . $endpoint;

        // BUG FIX التاريخي (كان الـ Content-Type بينسى هنا) اتحل دلوقتي
        // بشكل بنيوي — كل method بقى بيمر إجباريًا من build_signed_headers().
        $response = $this->request_with_breaker($url, 'GET', '', 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        }
        if ($code === 403) {
            return new WP_Error('api_forbidden', $body['error'] ?? 'Multi-store management requires the Agency plan.');
        }
        return new WP_Error('api_error', $body['error'] ?? 'Failed to fetch stores.');
    }

    /**
     * Register a new managed store domain.
     *
     * @param string $store_url As entered by the merchant (unnormalized).
     * @param string $label     Optional merchant-facing name.
     * @return array|WP_Error
     */
    public function store_add($store_url, $label = '') {
        $endpoint = '/stores';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'storeUrl' => $store_url,
            'label'    => $label ?: null,
        ]);

        $response = $this->request_with_breaker($url, 'POST', $body, 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body_decoded;
        }
        if ($code === 409) {
            return new WP_Error('api_conflict', 'This domain is already registered as a store.');
        }
        if ($code === 403) {
            return new WP_Error('api_forbidden', $body_decoded['error'] ?? 'Multi-store management requires the Agency plan.');
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to add store.');
    }

    /**
     * Update a store's label and/or active state (rename / deactivate /
     * reactivate all go through this single signed PUT).
     *
     * @param string     $id
     * @param array      $data Any of: ['label' => string, 'isActive' => bool]
     * @return array|WP_Error
     */
    public function store_update($id, $data) {
        $endpoint = '/stores/' . rawurlencode($id);
        $url      = $this->base_url . $endpoint;
        $body     = json_encode($data);

        $response = $this->request_with_breaker($url, 'PUT', $body, 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body_decoded;
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to update store.');
    }

    /**
     * Deactivate a store (soft-delete — history is preserved server-side).
     *
     * @param string $id
     * @return true|WP_Error
     */
    public function store_deactivate($id) {
        $endpoint = '/stores/' . rawurlencode($id);
        $url      = $this->base_url . $endpoint;

        $response = $this->request_with_breaker($url, 'DELETE', '', 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 200 && $code < 300) {
            return true;
        }
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to deactivate store.');
    }

    /**
     * Save the merchant's alert webhook (Slack/Discord/custom).
     *
     * @param string $url          Destination webhook URL (already validated
     *                             for scheme/SSRF by the caller).
     * @param string $type         slack|discord|custom
     * @param string $resolved_ip  The IP the URL's host resolved to at
     *                             validation time (see
     *                             chargeguard_host_is_private_or_reserved()),
     *                             forwarded so the backend can pin/re-check
     *                             delivery against DNS rebinding.
     * @return array|WP_Error
     */
    public function webhook_save($url, $type, $resolved_ip = '') {
        $endpoint = '/settings/webhook';
        $api_url  = $this->base_url . $endpoint;
        $body     = json_encode([
            'webhookUrl'  => $url,
            'webhookType' => $type,
            'resolvedIp'  => $resolved_ip,
        ]);

        $response = $this->request_with_breaker($api_url, 'POST', $body, 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body_decoded;
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to save webhook settings.');
    }

    /**
     * Send a test notification to the configured webhook.
     *
     * @return true|WP_Error
     */
    public function webhook_test() {
        $endpoint = '/settings/webhook/test';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([]); // '{}' — ثابتة، مش سترينج فاضية

        $response = $this->request_with_breaker($url, 'POST', $body, 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 200 && $code < 300) {
            return true;
        }
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Test failed. Check your webhook URL.');
    }

    /**
     * Verify the current API key and fetch the tenant's plan/subscription
     * status directly from the backend. Used by the settings page to
     * plan-gate Pro-only UI (e.g. the Notification Channels card) so a
     * Starter merchant sees a soft-lock prompt instead of a form the
     * backend will silently reject with 403.
     *
     * Deliberately unsigned (no HMAC) — mirrors GET /risk/verify-key's own
     * documented design as a lightweight, low-value-target probe endpoint.
     *
     * @return array|WP_Error Decoded body (includes 'plan'), or WP_Error.
     */
    public function verify_key() {
        $endpoint = '/risk/verify-key';
        $url      = $this->base_url . $endpoint;

        $response = wp_remote_get($url, [
            'timeout' => 10,
            'headers' => ['X-API-Key' => $this->api_key],
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300 && !empty($body['valid'])) {
            return $body;
        }
        return new WP_Error('api_error', $body['message'] ?? 'Failed to verify API key.');
    }

    /**
     * Fetch current webhook settings/status for the connected tenant.
     *
     * @return array|WP_Error
     */
    public function webhook_status() {
        $endpoint = '/settings/webhook';
        $url      = $this->base_url . $endpoint;

        $response = $this->request_with_breaker($url, 'GET', '', 15);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        }
        return new WP_Error('api_error', $body['error'] ?? 'Failed to fetch webhook status.');
    }

    /**
     * Fetch country risk override settings for the connected tenant.
     *
     * @return array|WP_Error
     */
    public function geo_overrides_get() {
        $endpoint = '/settings/country-overrides';
        $url      = $this->base_url . $endpoint;

        $response = $this->request_with_breaker($url, 'GET', '', 10);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        }
        return new WP_Error('api_error', $body['error'] ?? 'Failed to fetch geo settings.');
    }

    /**
     * Save a per-country geo-risk override.
     *
     * @param string $country_code ISO 3166-1 alpha-2 code.
     * @param string $override     allow|escalate|smart
     * @return array|WP_Error
     */
    public function geo_override_save($country_code, $override) {
        $endpoint = '/settings/country-overrides';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'updates' => [
                [
                    'countryCode' => strtoupper($country_code),
                    'override'    => $override,
                ],
            ],
        ]);

        $response = $this->request_with_breaker($url, 'PUT', $body, 10);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body_decoded;
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to save override.');
    }

    /**
     * Requests a server-signed device token from the backend
     * (POST /risk/device-token). The plugin stores the returned value as
     * an HttpOnly cookie (see class-dynamic-firewall.php
     * maybe_issue_device_token()) — the client's own JavaScript can never
     * read or overwrite it, which is the point: a fresh valid token
     * requires this authenticated, signed round trip, not a console
     * command against document.cookie.
     *
     * Goes through request_with_breaker() like every other call in this
     * class — if the backend is unreachable, this simply fails (WP_Error)
     * and the caller falls back to the existing unsigned chargeguard_fp
     * flow, exactly as before this feature existed. No new fail-open
     * surface is introduced.
     *
     * @param string $ip The visitor's resolved IP (ChargeGuard_Dynamic_Firewall::get_client_ip()).
     * @return string|WP_Error The opaque token, or WP_Error on failure.
     */
    public function mint_device_token($ip = '') {
        $endpoint = '/risk/device-token';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode(['ip' => $ip]);

        $response = $this->request_with_breaker($url, 'POST', $body, 4);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300 && !empty($body_decoded['token'])) {
            return $body_decoded['token'];
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to mint device token');
    }

    /**
     * Requests an email OTP for the graduated 'challenge' step-up tier
     * (see routes/risk.js's /evaluate section 1c-ii and
     * globalRotationDetector.js). Goes through request_with_breaker() like
     * evaluate_risk()/mint_device_token() — this sits on the live checkout
     * path, not a one-off startup check like self_test()/reconcile_order().
     *
     * @param string $device_fp Untrusted, client-supplied — see the trust-boundary warning in class-dynamic-firewall.php.
     * @param string $email
     * @return array|WP_Error Decoded body (includes 'emailSent', 'expiresInSeconds') on success, WP_Error on failure/unreachable.
     */
    public function request_challenge($device_fp, $email) {
        $endpoint = '/risk/challenge/request';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'deviceFingerprint' => $device_fp,
            'email'             => $email,
        ]);

        // Slightly above the backend's own ~2-attempt/3s email-retry
        // budget (see sendChallengeOtpEmail's RETRIES comment) so this
        // request isn't cut off by our own HTTP timeout before the
        // backend has finished trying to send.
        $response = $this->request_with_breaker($url, 'POST', $body, 8);

        if (is_wp_error($response)) {
            return $response;
        }

        $code         = wp_remote_retrieve_response_code($response);
        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body_decoded; // { success, emailSent, expiresInSeconds }
        }

        // 429 = the backend's device/email gate answered on purpose ("slow down"). It is NOT a delivery
        // failure, so it gets its own error code and callers must never fail open on it.
        if ($code === 429) {
            return new WP_Error('chargeguard_challenge_rate_limited', (is_array($body_decoded) && isset($body_decoded['error'])) ? (string) $body_decoded['error'] : 'Too many verification requests. Please wait a few minutes.');
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Failed to request verification code.');
    }

    /**
     * Verifies an OTP code for the graduated 'challenge' tier. On success,
     * the backend mints and returns a signed 24h challenge ticket (see
     * deviceToken.js's mintChallengeTicket) that the caller should store
     * as the chargeguard_ct HttpOnly cookie.
     *
     * Mirrors evaluate_risk()'s 403-with-decision pattern: a 400 response
     * with a `verified` key present is an INTENTIONAL, checked outcome
     * (wrong/expired code, or too-many-attempts) — not an API failure —
     * so it is returned as a normal array, not collapsed into a WP_Error.
     * Collapsing it would make "the code was actually wrong" indistinguishable
     * from "the backend is unreachable," which the caller needs to tell apart
     * to decide whether to fail open or show the customer an actionable message.
     *
     * @param string $code
     * @param string $device_fp
     * @param string $email
     * @return array|WP_Error {verified: bool, ticket?: string, error?: string} on any answered response, WP_Error only on genuine network/backend failure.
     */
    public function verify_challenge($code, $device_fp, $email) {
        $endpoint = '/risk/challenge/verify';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'code'              => $code,
            'deviceFingerprint' => $device_fp,
            'email'             => $email,
        ]);

        $response = $this->request_with_breaker($url, 'POST', $body, 6);

        if (is_wp_error($response)) {
            return $response;
        }

        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);

        // Any response carrying a 'verified' key (true or false) is an
        // answered, intentional result — including 400 (wrong code) and
        // 429 (too many attempts). Only a response with NEITHER a 2xx
        // status NOR a 'verified' key is a genuine API failure.
        if (is_array($body_decoded) && array_key_exists('verified', $body_decoded)) {
            return $body_decoded;
        }
        return new WP_Error('api_error', $body_decoded['error'] ?? 'Verification failed.');
    }

    /**
     * توليد توقيع HMAC-SHA256 مطابق لتوقيع WooCommerce webhook.
     *
     * @param string $raw_body الجسم الخام للطلب.
     * @return string التوقيع بصيغة base64.
     */
    private function generate_hmac($raw_body, $timestamp, $domain, $request_id, $method, $path) {
        // v3: يضيف request_id صريح جوه الرسالة الموقّعة، فوق domain-binding
        // بتاع v2. الـ request_id ده هو نفسه مفتاح الـ idempotency اللي
        // الـ backend بيستخدمه يعرف إن ده retry لنفس العملية المنطقية —
        // وده معناه إنه لازم يفضل ثابت مع كل retry فعلي لنفس النداء
        // المنطقي، حتى لو الـ timestamp (وبالتالي التوقيع نفسه) اتجدّد مع
        // كل محاولة (شوف build_signed_headers/request_with_breaker تحت).
        // وبما إن request_id جوه السلسلة الموقّعة، مهاجم ملقطش السر
        // مايقدرش يغيّر request_id لتوقيع ملتقط من غيره — أي تغيير فيه
        // بيكسر التوقيع.
        $signed_string = $timestamp . '.' . $domain . '.' . $request_id . '.' . strtoupper($method) . '.' . $path . "\n" . $raw_body;
        return 'v3=' . hash_hmac('sha256', $signed_string, $this->webhook_secret);
    }

    /**
     * بناء الـ headers الموقّعة كاملة لمحاولة HTTP واحدة فعلية. بتتنادى من
     * جديد مع كل محاولة (بما فيها الـ retry) من جوه request_with_breaker() —
     * كل محاولة بتاخد timestamp وتوقيع طازة، لكن بنفس $request_id اللي
     * اتبعت لها (متولّد مرة واحدة بس لكل نداء منطقي)، وده اللي بيخلي الـ
     * backend يتعامل مع الـ retry على إنه "نفس العملية" بدل ما ينفّذ
     * handler فيه side effect مرتين، أو يرفض retry لطلب نجح فعلاً أول مرة.
     *
     * @param string $raw_body
     * @param string $request_id
     * @return array Header map جاهزة لـ wp_remote_request()'s 'headers'.
     */
    private function build_signed_headers($raw_body, $request_id, $method, $url) {
        $domain    = wp_parse_url( home_url(), PHP_URL_HOST );
        $timestamp = (string) time();
        // Method + path exactly as sent (no query). An unparsable URL gives '' and the server rejects it.
        $path      = wp_parse_url($url, PHP_URL_PATH);
        $path      = is_string($path) ? $path : '';
        $signature = $this->generate_hmac($raw_body, $timestamp, $domain, $request_id, $method, $path);

        return [
            'Content-Type'             => 'application/json',
            'X-API-Key'                => $this->api_key,
            'X-Store-Domain'           => $domain,
            'X-ChargeGuard-Signature'  => $signature,
            'X-ChargeGuard-Timestamp'  => $timestamp,
            'X-ChargeGuard-Request-Id' => $request_id,
        ];
    }

    /**
     * إرسال طلب تقييم مخاطر إلى ChargeGuard API.
     *
     * @param array $data بيانات الطلب.
     * @return array|WP_Error
     */
    public function evaluate_risk($data) {
        $endpoint = '/risk/evaluate';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode($data);

        $response = $this->request_with_breaker($url, 'POST', $body, 5);

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        }

        // A 403 with a `decision` field is an intentional block decision
        // (blacklist hit or quota exceeded), not an API failure — the
        // caller (intercept_checkout / intercept_checkout_block) needs the
        // full body to read `decision`, `flags`, and `blocked_reason`.
        // Collapsing it into a generic WP_Error would make a real block
        // indistinguishable from "the API is unreachable."
        if ($code === 403 && is_array($body) && isset($body['decision'])) {
            return $body;
        }

        return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
    }

    /**
     * Perform a lightweight signed round-trip against the backend to
     * confirm the currently-configured signing secret (new dedicated
     * secret, or the webhookSecret fallback — whichever __construct()
     * resolved) is actually the one the backend has on file for this
     * merchant. Intended to be called once, immediately after connect,
     * so a misconfigured or unpersisted signing secret is caught before
     * the merchant believes their store is protected — rather than
     * failing silently on every real risk evaluation afterward.
     *
     * Deliberately bypasses the circuit breaker (like reconcile_order):
     * this is a one-off startup check, not steady-state traffic, and a
     * signature failure here is a configuration problem, not a signal
     * that the API is generally unreachable.
     *
     * @return true|WP_Error True if the backend confirmed the signature;
     *                       WP_Error otherwise (auth failure or network error).
     */
    public function self_test() {
        $endpoint = '/auth/self-test';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode(['check' => 'signing_secret']);
        $headers  = $this->build_signed_headers($body, wp_generate_uuid4(), 'POST', $url);

        $response = wp_remote_post($url, [
            'method'  => 'POST',
            'headers' => $headers,
            'body'    => $body,
            'timeout' => 10,
        ]);

        if (is_wp_error($response)) {
            return new WP_Error('chargeguard_self_test_network', 'Could not reach ChargeGuard to verify signing: ' . $response->get_error_message());
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 200 && $code < 300) {
            return true;
        }

        if ($code === 401 || $code === 403) {
            return new WP_Error('chargeguard_self_test_signature', 'ChargeGuard rejected the request signature — the signing secret does not match what the backend has stored.');
        }

        $body_decoded = json_decode(wp_remote_retrieve_body($response), true);
        return new WP_Error('chargeguard_self_test_failed', $body_decoded['error'] ?? ('Self-test failed with HTTP ' . $code));
    }

    /**
     * Link a temporary pre-order risk evaluation (created before the real
     * WooCommerce order existed) to the real order ID once it's known.
     *
     * Intentionally non-blocking: by the time this fires the checkout has
     * already succeeded and the order is saved, so a slow or unreachable
     * backend must never surface an error to the customer or delay the
     * response. This also deliberately bypasses the circuit breaker —
     * reconciliation failures are not a signal that risk-scoring itself is
     * degraded, and shouldn't trip the merchant-facing fail-open notice.
     *
     * @param string     $pre_order_id The throwaway 'pre_...' ID originally sent to /risk/evaluate.
     * @param int|string $real_order_id The real WooCommerce order ID.
     * @return void
     */
    public function reconcile_order($pre_order_id, $real_order_id) {
        if (empty($pre_order_id) || empty($real_order_id)) {
            return;
        }

        $endpoint = '/risk/reconcile';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode([
            'preOrderId' => $pre_order_id,
            'orderId'    => (string) $real_order_id,
        ]);
        $headers  = $this->build_signed_headers($body, wp_generate_uuid4(), 'POST', $url);

        $response = wp_remote_post($url, [
            'method'   => 'POST',
            'blocking' => false,
            'timeout'  => 3,
            'headers'  => $headers,
            'body'     => $body,
        ]);

        if (is_wp_error($response)) {
            error_log('ChargeGuard: reconcile_order failed to dispatch — pre_order_id: ' . $pre_order_id . ', real_order_id: ' . $real_order_id . ', error: ' . $response->get_error_message());
        }
    }

    /**
     * Show a dashboard notice while the circuit breaker is open, so the
     * merchant knows fraud protection is temporarily running in degraded
     * (fail-open) mode.
     */
    public function maybe_show_circuit_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        if (!get_transient(self::CIRCUIT_OPEN_TRANSIENT)) {
            return;
        }
        $status = get_option(self::CIRCUIT_STATUS_OPTION, []);
        $reopens_in = isset($status['reopens_in']) ? (int) $status['reopens_in'] : CHARGEGUARD_CIRCUIT_OPEN_SECONDS;
        $behavior = get_option('chargeguard_api_down_behavior', 'local_checks');
        $mode_text = $behavior === 'block_all'
            ? __('blocking all new orders until it recovers', 'chargeguard-woocommerce')
            : ($behavior === 'allow_all'
                ? __('approving all orders unscored — this store has opted out of the safer default; see Firewall Settings', 'chargeguard-woocommerce')
                : __('using local fallback checks (device blacklist + a hard per-IP rate limit) instead of full scoring', 'chargeguard-woocommerce'));
        ?>
        <div class="notice notice-warning">
            <p>
                <strong>ChargeGuard:</strong>
                <?php
                printf(
                    esc_html__('The fraud-scoring API is currently unreachable. Your store is %1$s. Full protection resumes automatically within %2$s seconds of the API becoming reachable again. Configure this fallback behavior under ChargeGuard → Firewall Settings.', 'chargeguard-woocommerce'),
                    esc_html($mode_text),
                    esc_html($reopens_in)
                );
                ?>
            </p>
        </div>
        <?php
    }
}