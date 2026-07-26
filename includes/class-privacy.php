<?php
/**
 * ChargeGuard - Privacy / GDPR Integration
 *
 * Registers ChargeGuard's data with WordPress's built-in Personal Data
 * Export and Personal Data Erasure tools (Tools → Export/Erase Personal
 * Data), and suggests privacy-policy language covering the data this
 * plugin sends to the ChargeGuard fraud-prevention API.
 *
 * Scope: only the two order-meta keys ChargeGuard itself writes
 * (_chargeguard_device_fingerprint, _chargeguard_payment_intent_id).
 * Orders are never deleted — only this plugin's meta is removed.
 *
 * @package ChargeGuard_WooCommerce
 */

defined('ABSPATH') || exit;

class ChargeGuard_Privacy {

    const ORDERS_PER_PAGE = 10;

    public function __construct() {
        add_filter('woocommerce_privacy_exporters', [$this, 'register_exporter']);
        add_filter('woocommerce_privacy_erasers', [$this, 'register_eraser']);
        add_action('admin_init', [$this, 'add_privacy_policy_content']);
    }

    /**
     * Register ChargeGuard's exporter with WooCommerce's privacy tools.
     *
     * @param array $exporters
     * @return array
     */
    public function register_exporter($exporters) {
        $exporters['chargeguard-woocommerce'] = [
            'exporter_friendly_name' => __('ChargeGuard Fraud Prevention Data', 'chargeguard-woocommerce'),
            'callback'               => [$this, 'export_data'],
        ];
        return $exporters;
    }

    /**
     * Register ChargeGuard's eraser with WooCommerce's privacy tools.
     *
     * @param array $erasers
     * @return array
     */
    public function register_eraser($erasers) {
        $erasers['chargeguard-woocommerce'] = [
            'eraser_friendly_name' => __('ChargeGuard Fraud Prevention Data', 'chargeguard-woocommerce'),
            'callback'             => [$this, 'erase_data'],
        ];
        return $erasers;
    }

    /**
     * Export the device fingerprint hash for every order matching this
     * email address. Paginated the same way WooCommerce core's own
     * order exporter is, since a customer can have many orders.
     *
     * @param string $email_address
     * @param int    $page
     * @return array
     */
    public function export_data($email_address, $page = 1) {
        $page = (int) $page;

        $orders = wc_get_orders([
            'billing_email' => $email_address,
            'limit'         => self::ORDERS_PER_PAGE,
            'page'          => $page,
            'orderby'       => 'date',
            'order'         => 'DESC',
            'return'        => 'objects',
        ]);

        $export_items = [];

        foreach ($orders as $order) {
            $fingerprint = $order->get_meta('_chargeguard_device_fingerprint');
            $pre_order_id_item = $this->export_pre_order_id_item($order);

            if (empty($fingerprint) && !$pre_order_id_item) {
                continue;
            }

            $item_data = [
                [
                    'name'  => __('Order', 'chargeguard-woocommerce'),
                    'value' => $order->get_order_number(),
                ],
            ];

            if (!empty($fingerprint)) {
                $item_data[] = [
                    'name'  => __('Device fingerprint (a SHA-256 hash derived from the browser, not the raw browser data itself)', 'chargeguard-woocommerce'),
                    'value' => $fingerprint,
                ];
            }

            if ($pre_order_id_item) {
                $item_data[] = $pre_order_id_item;
            }

            $export_items[] = [
                'group_id'    => 'chargeguard_orders',
                'group_label' => __('ChargeGuard Fraud Prevention Data', 'chargeguard-woocommerce'),
                'item_id'     => 'chargeguard-order-' . $order->get_id(),
                'data'        => $item_data,
            ];
        }

        return [
            'data' => $export_items,
            'done' => count($orders) < self::ORDERS_PER_PAGE,
        ];
    }

    /**
     * Include _chargeguard_pre_order_id in the export whenever present,
     * as its own item alongside the fingerprint entry above. Kept as a
     * separate small method rather than inlined into export_data()'s
     * loop so the "is this a personal-data field?" labeling stays
     * next to the field it describes; called from export_data() below.
     *
     * This is not personal data — it is an internal correlation ID
     * (pre_<uniqid>) generated before a Classic-checkout order exists,
     * used only to match ChargeGuard's pre-order risk evaluation to the
     * resulting order. Included here anyway, clearly labeled, so the
     * export remains a complete and trustworthy inventory of every
     * ChargeGuard meta key stored on the order.
     *
     * @param WC_Order $order
     * @return array|null
     */
    private function export_pre_order_id_item($order) {
        $pre_order_id = $order->get_meta('_chargeguard_pre_order_id');
        if (empty($pre_order_id)) {
            return null;
        }
        return [
            'name'  => __('Pre-order correlation ID (an internal technical identifier, not personal data)', 'chargeguard-woocommerce'),
            'value' => $pre_order_id,
        ];
    }

    /**
     * Erase ChargeGuard's meta from every order matching this email
     * address. Never deletes the order itself — only clears the two
     * meta keys this plugin writes.
     *
     * @param string $email_address
     * @param int    $page
     * @return array
     */
    public function erase_data($email_address, $page = 1) {
        $page = (int) $page;

        $orders = wc_get_orders([
            'billing_email' => $email_address,
            'limit'         => self::ORDERS_PER_PAGE,
            'page'          => $page,
            'orderby'       => 'date',
            'order'         => 'DESC',
            'return'        => 'objects',
        ]);

        $items_removed = false;
        $cleaned_count = 0;

        foreach ($orders as $order) {
            $has_fingerprint  = (bool) $order->get_meta('_chargeguard_device_fingerprint');
            $has_intent_id    = (bool) $order->get_meta('_chargeguard_payment_intent_id');
            $has_pre_order_id = (bool) $order->get_meta('_chargeguard_pre_order_id');

            if (!$has_fingerprint && !$has_intent_id && !$has_pre_order_id) {
                continue;
            }

            $order->delete_meta_data('_chargeguard_device_fingerprint');
            $order->delete_meta_data('_chargeguard_payment_intent_id');
            $order->delete_meta_data('_chargeguard_pre_order_id');
            $order->save_meta_data();

            $items_removed = true;
            $cleaned_count++;
        }

        $messages = [];
        if ($items_removed) {
            $messages[] = sprintf(
                /* translators: %d: number of orders cleaned */
                _n(
                    'Removed ChargeGuard fingerprint data from %d order.',
                    'Removed ChargeGuard fingerprint data from %d orders.',
                    $cleaned_count,
                    'chargeguard-woocommerce'
                ),
                $cleaned_count
            );
        }

        // Local data is fully handled above, but the ChargeGuard cloud
        // fraud-prevention service retains its own copy of this
        // customer's email, IP, device fingerprint, and card BIN/brand/
        // country (if available) — this plugin has no backend deletion
        // endpoint wired up yet, so completing the erasure requires a
        // separate, manual request to ChargeGuard support. Always shown,
        // even if no local meta was found, since backend data can exist
        // independently of local order meta.
        //
        // Automated cloud erasure via send_backend_erasure_request() is
        // implemented but PARKED (not called from here) until the
        // backend's DELETE /api/privacy/erase endpoint exists and is
        // confirmed working — see that method's docblock for activation
        // steps.
        $messages[] = __(
            'ChargeGuard also stores this customer\'s data (email, IP, device fingerprint, and card details where applicable) on its cloud fraud-prevention service. This local erasure does NOT remove that data — please contact ChargeGuard support to request deletion there as well.',
            'chargeguard-woocommerce'
        );

        return [
            'items_removed'  => $items_removed,
            'items_retained' => false, // ChargeGuard has no legal-hold reason to keep this meta.
            'messages'       => $messages,
            'done'           => count($orders) < self::ORDERS_PER_PAGE,
        ];
    }

    /**
     * Request deletion of this customer's data held by the ChargeGuard
     * cloud fraud-prevention service (email, IP, device fingerprint,
     * card BIN/brand/country, and any whitelist/blacklist entries
     * referencing this email or an IP tied to it). Best-effort: local
     * erasure in erase_data() has already completed regardless of the
     * outcome here, so a failure is reported to the merchant rather
     * than silently swallowed.
     *
     * NOTE: assumes a `DELETE /api/privacy/erase` endpoint on the
     * ChargeGuard backend, keyed by email, does not yet exist and must
     * be implemented server-side before this will succeed.
     *
     * @param string $email_address
     * @return array{success: bool, message: string}
     */
    private function send_backend_erasure_request($email_address) {
        // PARKED — not yet wired into erase_data() or any hook. Do not
        // activate until the backend's `DELETE /api/privacy/erase`
        // endpoint exists and has been tested end-to-end; calling this
        // today would fire a network request against an endpoint that
        // does not exist yet, on every erasure request, for no benefit.
        // To activate: confirm the backend endpoint is live, remove the
        // early return below, call this method from erase_data(), and
        // update erase_data()'s merchant-facing message to reflect
        // automated (rather than manual) cloud erasure.
        return [
            'success' => false,
            'message' => __(
                'Automated cloud erasure is not yet available; this method is parked pending a backend endpoint.',
                'chargeguard-woocommerce'
            ),
        ];
        // Unreachable below until the return above is removed — left
        // intact intentionally so the implementation is ready to go the
        // day the backend endpoint ships.
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = function_exists('chargeguard_get_secret_option')
            ? chargeguard_get_secret_option('chargeguard_api_key')
            : get_option('chargeguard_api_key');

        if (!$merchant_id || !$api_key) {
            // Store isn't connected to ChargeGuard — nothing on the
            // backend to erase, so this isn't a failure worth alarming
            // the merchant about.
            return [
                'success' => true,
                'message' => __(
                    'ChargeGuard is not connected to a cloud account for this store, so no cloud data existed to erase.',
                    'chargeguard-woocommerce'
                ),
            ];
        }

        $response = wp_remote_request(
            'https://chargeguard-api.onrender.com/api/privacy/erase',
            [
                'method'  => 'DELETE',
                'timeout' => 15,
                'headers' => [
                    'Content-Type'  => 'application/json',
                    'x-api-key'     => $api_key,
                    'x-merchant-id' => $merchant_id,
                ],
                'body' => json_encode(['email' => $email_address]),
            ]
        );

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'message' => __(
                    'Could not reach the ChargeGuard fraud-prevention service to erase this customer\'s cloud data. Local data has been removed, but please contact ChargeGuard support to confirm the cloud copy is deleted.',
                    'chargeguard-woocommerce'
                ),
            ];
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code === 200) {
            return [
                'success' => true,
                'message' => __(
                    'Requested deletion of this customer\'s data from the ChargeGuard cloud fraud-prevention service.',
                    'chargeguard-woocommerce'
                ),
            ];
        }

        return [
            'success' => false,
            'message' => sprintf(
                /* translators: %d: HTTP response code from the ChargeGuard backend */
                __(
                    'The ChargeGuard fraud-prevention service did not confirm deletion of this customer\'s cloud data (response code %d). Local data has been removed, but please contact ChargeGuard support to confirm the cloud copy is deleted.',
                    'chargeguard-woocommerce'
                ),
                $code
            ),
        ];
    }

    /**
     * Suggest privacy-policy language for the merchant, covering data
     * sent to the ChargeGuard cloud API during risk evaluation.
     */
    public function add_privacy_policy_content() {
        if (!function_exists('wp_add_privacy_policy_content')) {
            return;
        }

        $content = '<p class="wp-policy-help">' . wp_kses_post(__(
            'When you place an order, we share your email address, IP address, and a hashed representation of your device (not raw browsing data) with ChargeGuard, a third-party fraud-prevention service, solely to assess the risk of the transaction. This data is transmitted over an encrypted connection.',
            'chargeguard-woocommerce'
        )) . '</p><p class="wp-policy-help">' . wp_kses_post(__(
            'Once this store is connected to ChargeGuard, an automated order notification is also sent to ChargeGuard for every new order, in addition to the risk-assessment data described above. This notification includes the order details you provide at checkout: billing and shipping name and address, phone number, the products and quantities ordered, any coupon codes used, and the payment method. This is used to help detect fraud patterns across orders, such as repeated use of stolen payment details or coordinated fraudulent purchases.',
            'chargeguard-woocommerce'
        )) . '</p><p class="wp-policy-help">' . wp_kses_post(__(
            'Using the "Erase Personal Data" tool removes ChargeGuard data stored locally in WordPress automatically. However, the ChargeGuard fraud-prevention service also retains a copy of the data described above (email, IP, device fingerprint, order and billing/shipping details, and card BIN/brand/country where applicable) on its own servers. Completing an erasure request in full requires contacting ChargeGuard support separately to request deletion of this data.',
            'chargeguard-woocommerce'
        )) . '</p>';

        wp_add_privacy_policy_content(
            __('ChargeGuard for WooCommerce', 'chargeguard-woocommerce'),
            $content
        );
    }
}