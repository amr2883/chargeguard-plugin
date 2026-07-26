<?php
/**
 * ChargeGuard PayPal Webhook Handler
 *
 * يستقبل Webhook من PayPal، يستخرج بيانات الدفع، ويرسلها إلى ChargeGuard.
 *
 * @package ChargeGuard_WooCommerce
 */

class ChargeGuard_PayPal_Webhook {

    use ChargeGuard_Auto_Block_Trait;

    private $api_client;

    public function __construct() {
        $this->api_client = new ChargeGuard_API_Client();
        add_action( 'rest_api_init', [ $this, 'register_rest_route' ] );

        // Mirrors ChargeGuard_Stripe_Webhook's consume_pending_enrichment()
        // pattern exactly. PayPal's find_order_id() already tries
        // _transaction_id meta as one of its resolution paths — by the
        // time woocommerce_payment_complete fires, WooCommerce's PayPal
        // gateway has normally set that meta (via $order->get_transaction_id()),
        // so this is the earliest reliable point to re-resolve an order
        // that wasn't found at webhook-delivery time.
        add_action( 'woocommerce_payment_complete', [ $this, 'consume_pending_enrichment' ] );
    }

    /**
     * تسجيل REST API endpoint لاستقبال PayPal Webhook.
     */
    public function register_rest_route() {
        register_rest_route( 'chargeguard/v1', '/paypal-webhook', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'handle_webhook' ],
            'permission_callback' => '__return_true',
        ] );
    }

    /**
     * معالجة PayPal Webhook الوارد.
     *
     * @param WP_REST_Request $request الطلب الوارد.
     * @return WP_REST_Response
     */
    public function handle_webhook( $request ) {

        // ── 1. التحقق من أن التكامل مفعّل ──────────────────────────
        if ( get_option( 'chargeguard_paypal_enabled', '0' ) !== '1' ) {
            return new WP_REST_Response( [ 'status' => 'disabled' ], 200 );
        }

        // ── 2. Idempotency — منع معالجة نفس الحدث مرتين ────────────
        $transmission_id = $request->get_header( 'paypal_transmission_id' );
        $cache_key       = $transmission_id
            ? 'cg_pp_processed_' . md5( $transmission_id )
            : null;

        if ( $cache_key && get_transient( $cache_key ) ) {
            return new WP_REST_Response( [ 'status' => 'already_processed' ], 200 );
        }

        // ── 3. قراءة الـ payload ─────────────────────────────────────
        $payload_raw = $request->get_body();
        $payload     = json_decode( $payload_raw, true );

        if ( empty( $payload ) || ! isset( $payload['event_type'] ) ) {
            return new WP_REST_Response( [ 'error' => 'Invalid payload' ], 400 );
        }

        // ── 4. فلترة الأحداث — نعالج فقط ما يهمنا ──────────────────
        $supported_events = [
            'PAYMENT.CAPTURE.COMPLETED',
            'PAYMENT.CAPTURE.DENIED',
            'CHECKOUT.ORDER.APPROVED',
            'PAYMENT.AUTHORIZATION.CREATED',
            // CUSTOMER.DISPUTE.RESOLVED — NOT RISK.DISPUTE.CREATED. The
            // creation-time event fires the moment a dispute is OPENED,
            // before PayPal has decided anything; its payload carries no
            // outcome field. Only the RESOLVED event's resource includes
            // dispute_outcome.outcome_code, the one trustworthy signal for
            // "did the merchant actually lose this dispute." See
            // handle_dispute_event() below.
            'CUSTOMER.DISPUTE.RESOLVED',
        ];

        if ( ! in_array( $payload['event_type'], $supported_events, true ) ) {
            return new WP_REST_Response( [ 'status' => 'ignored', 'event' => $payload['event_type'] ], 200 );
        }

        // ── 4b. Per-IP rate limit — placed after the cheap idempotency/
        // event-type checks above but before verify_webhook_signature(),
        // which makes a real outbound network call to PayPal (OAuth token
        // fetch + verify-webhook-signature). This is the same
        // transient-based pattern already used in
        // ChargeGuard_Dynamic_Firewall::ajax_check_fingerprint(), applied
        // here because this REST route is public/unauthenticated
        // (permission_callback => __return_true) and the event_type
        // allow-list alone is not a meaningful barrier — the values in it
        // are public PayPal documentation, not a secret. Without this,
        // an attacker can drive unlimited outbound requests from this
        // server to PayPal's API using nothing but a guessed event_type
        // string, at cost to this store's bandwidth/connection pool and
        // at risk of exhausting PayPal's own rate limit for this
        // merchant's real webhook deliveries.
        $rl_ip  = class_exists( 'ChargeGuard_Dynamic_Firewall' ) ? ChargeGuard_Dynamic_Firewall::get_client_ip() : '';
        $rl_ip  = $rl_ip !== '' ? $rl_ip : 'unknown';
        $rl_key = 'chargeguard_pp_rate_' . md5( $rl_ip );
        $rl_count = get_transient( $rl_key );
        if ( $rl_count === false ) {
            set_transient( $rl_key, 1, 60 );
        } elseif ( $rl_count >= 10 ) {
            // Generic 200 with no error detail: avoids leaking anything
            // an attacker could use to distinguish "rate limited" from
            // "processed", and — critically for a webhook endpoint —
            // avoids returning a 4xx/5xx that would make PayPal treat
            // this as a failed delivery and schedule retries, which
            // would only add more requests during an already-abusive
            // window. See class docblock / justification for full
            // reasoning.
            return new WP_REST_Response( [ 'status' => 'rate_limited' ], 200 );
        } else {
            set_transient( $rl_key, $rl_count + 1, 60 );
        }

        // ── 5. التحقق من توقيع PayPal (Remote Verification) ─────────
        $verified = $this->verify_webhook_signature( $request, $payload_raw );
        if ( ! $verified ) {
            return new WP_REST_Response( [ 'error' => 'Invalid signature' ], 403 );
        }

        // ── 6. استخراج البيانات من الـ payload ──────────────────────
        $extracted = $this->extract_payment_data( $payload );

        if ( ! $extracted ) {
            // حدث لا يحتوي على بيانات دفع قابلة للمعالجة (مثل RISK.DISPUTE.CREATED)
            // handle_dispute_event() returns false only when a confirmed
            // dispute-loss send_feedback() call failed (transient backend
            // error or open circuit) — that path must not be marked
            // processed, so PayPal's own redelivery of this
            // transmission_id can retry it. Every other branch inside
            // handle_dispute_event() is deterministic given this payload
            // and returns true.
            $processed = $this->handle_dispute_event( $payload );

            if ( ! $processed ) {
                return new WP_REST_Response( [ 'error' => 'feedback dispatch failed' ], 500 );
            }

            if ( $cache_key ) {
                set_transient( $cache_key, 1, 48 * HOUR_IN_SECONDS );
            }
            return new WP_REST_Response( [ 'status' => 'handled', 'event' => $payload['event_type'] ], 200 );
        }

        // ── 8. الرد على PayPal فوراً قبل أي استدعاء خارجي ──────────
        // PayPal ينتظر 30 ثانية فقط — لا نخاطر بالتأخير
        // نُكمل المعالجة بعد الإرسال
        $response = new WP_REST_Response( [ 'status' => 'received' ], 200 );

        // ── 9. ربط الـ WooCommerce Order ─────────────────────────────
        $order_id = $this->find_order_id( $extracted, $payload );

        // No order resolved yet (webhook raced ahead of _transaction_id
        // meta being set) — queue the enrichment locally, keyed by
        // PayPal's txn_id, for consume_pending_enrichment() to pick up
        // on woocommerce_payment_complete. This is the fix for the
        // synthetic 'paypal_<txnId>' orderId that previously created a
        // permanently-orphaned PendingEnrichment row on the backend: the
        // backend can never resolve that synthetic ID to a real order,
        // so only the plugin — which alone learns the real order ID once
        // WooCommerce links it — can complete this enrichment.
        $has_card_or_payer_data = ! empty( $extracted['bin'] ) || ! empty( $extracted['last4'] ) || ! empty( $extracted['payer_email'] );

        if ( ! $order_id && ! empty( $extracted['txn_id'] ) && $has_card_or_payer_data ) {
            set_transient( 'chargeguard_pending_enrich_paypal_' . $extracted['txn_id'], [
                'orderId'     => null,
                'bin'         => $extracted['bin'] ?? null,
                'last4'       => $extracted['last4'] ?? null,
                'expMonth'    => $extracted['exp_month'] ?? null,
                'expYear'     => $extracted['exp_year'] ?? null,
                'brand'       => $extracted['brand'] ?? null,
                'cardBrand'   => $extracted['brand'] ?? null,
                'cardCountry' => $extracted['card_country'] ?? null,
                'funding'     => $extracted['funding'] ?? null,
                'issuer'      => null,
                'source'      => 'paypal',
                'paypalTxnId' => $extracted['txn_id'],
                'eventType'   => $payload['event_type'],
                'deviceToken' => null, // re-resolved fresh in consume_pending_enrichment()
            ], HOUR_IN_SECONDS );

            if ( $cache_key ) {
                set_transient( $cache_key, 1, 48 * HOUR_IN_SECONDS );
            }
            return new WP_REST_Response( [ 'status' => 'pending', 'message' => 'Order not found, enrichment queued locally.' ], 202 );
        }

        // Threads the checkout-time device token through to this
        // post-payment enrichment call — same rationale/meta key as
        // class-stripe-webhook.php::handle_webhook(). Null when there's
        // no resolved order, or on orders predating this fix / older
        // plugin versions; /enrich treats a missing token exactly like
        // today's unsigned fingerprint (deviceTrustFactor 1.0).
        $device_token = null;
        if ( $order_id ) {
            $order_for_token = wc_get_order( $order_id );
            if ( $order_for_token ) {
                $meta_token = $order_for_token->get_meta( '_chargeguard_device_token' );
                $device_token = ! empty( $meta_token ) ? $meta_token : null;
            }
        }

        // ── 10. بناء بيانات enrich وإرسالها ─────────────────────────
        $enrich_data = [
            'orderId'     => $order_id ? (string) $order_id : $this->generate_paypal_order_id( $payload ),
            'bin'         => $extracted['bin'] ?? null,
            'last4'       => $extracted['last4'] ?? null,
            'expMonth'    => $extracted['exp_month'] ?? null,
            'expYear'     => $extracted['exp_year'] ?? null,
            'brand'       => $extracted['brand'] ?? null,
            'cardBrand'   => $extracted['brand'] ?? null,
            'cardCountry' => $extracted['card_country'] ?? null,
            'funding'     => $extracted['funding'] ?? null,
            'issuer'      => null,
            'source'      => 'paypal',
            'paypalTxnId' => $extracted['txn_id'] ?? null,
            'eventType'   => $payload['event_type'],
            'deviceToken' => $device_token,
        ];

        // نرسل فقط إذا كان هناك BIN أو last4 (بيانات بطاقة حقيقية)
        $has_card_data = ! empty( $enrich_data['bin'] ) || ! empty( $enrich_data['last4'] );

        // Tracks whether this delivery reached a definitive outcome.
        // Stays true for the "nothing to send" fallthrough (no card data,
        // no payer email, or no resolved order) since there's no external
        // call whose failure we'd need to retry. Flipped to false only
        // when send_enrich() itself returns a WP_Error.
        $mark_processed = true;

        if ( $has_card_data ) {
            $result = $this->api_client->send_enrich( $enrich_data );

            if ( is_wp_error( $result ) ) {
                // Transient failure (network blip, backend 5xx, timeout).
                // Do NOT mark this transmission processed — leaving the
                // transient unset lets PayPal's own redelivery retry
                // enrichment instead of the order silently and
                // permanently losing its fraud data.
                $mark_processed = false;
            } elseif ( $order_id ) {
                // إذا كان القرار block وكانت الـ auto-block مفعلة وعندنا order_id
                //
                // Refund context is only populated for PAYMENT.CAPTURE.COMPLETED
                // — for every other subscribed event type (CHECKOUT.ORDER.APPROVED,
                // PAYMENT.AUTHORIZATION.CREATED, etc.) resource.id is NOT a capture
                // ID, and attempting a refund against it would target the wrong
                // PayPal object or simply 404.
                $refund_context = null;
                if ( $payload['event_type'] === 'PAYMENT.CAPTURE.COMPLETED' && ! empty( $extracted['txn_id'] ) ) {
                    $refund_context = [
                        'gateway'    => 'paypal',
                        'capture_id' => $extracted['txn_id'],
                    ];
                }

                $this->chargeguard_fire_device_fraud_hook( $result, $order_id, 'paypal_post_payment_block' );

                $this->chargeguard_maybe_block_order(
                    $result,
                    $order_id,
                    __( 'Blocked by ChargeGuard: Suspicious PayPal payment detected.', 'chargeguard-woocommerce' ),
                    $refund_context
                );
            }
        } elseif ( ! empty( $extracted['payer_email'] ) ) {
            // PayPal Balance payment — لا بطاقة، لكن نُسجّل الحدث للـ velocity tracking
            // نرسل للـ enrich بدون bin — سيُخزَّن كـ pendingEnrichment إذا لم يُوجد الطلب
            if ( $order_id ) {
                $enrich_data['orderId'] = (string) $order_id;
                $result = $this->api_client->send_enrich( $enrich_data );

                if ( is_wp_error( $result ) ) {
                    $mark_processed = false;
                }
            }
        }

        // ── Idempotency — mark processed only after a definitive outcome ──
        // Moved here from the old step 6 (right after signature
        // verification). Setting it that early meant a transient
        // send_enrich() failure still got marked "processed," so PayPal's
        // legitimate redelivery of that same transmission_id would be
        // swallowed by the already_processed check earlier in this
        // method — permanently dropping enrichment and any auto-block
        // decision for that order. This mirrors the Stripe handler's
        // placement: the transient is only written once we know there's
        // nothing left that a retry could usefully redo.
        if ( $cache_key && $mark_processed ) {
            set_transient( $cache_key, 1, 48 * HOUR_IN_SECONDS );
        }

        return $response;
    }

    /**
     * Consume any enrichment data queued by handle_webhook() for a PayPal
     * transaction that arrived before its order existed.
     *
     * Mirrors ChargeGuard_Stripe_Webhook::consume_pending_enrichment()
     * exactly. Fires on woocommerce_payment_complete rather than order
     * creation, because the PayPal transaction ID is not reliably present
     * as order meta/transaction_id until the gateway has actually
     * processed payment.
     *
     * At-least-once safe: the transient is deleted before the API call,
     * so a payment-complete hook firing twice for the same order is a
     * no-op on the second call. If the transient has expired (1h TTL) or
     * was never set, this silently returns — the common case, since most
     * PayPal webhooks resolve an order on the first attempt.
     *
     * @param int $order_id
     * @return void
     */
    public function consume_pending_enrichment( $order_id ) {
        $order = wc_get_order( $order_id );
        if ( ! $order ) {
            return;
        }

        // WooCommerce's PayPal-family gateways set this via
        // $order->set_transaction_id() by payment-complete time — the
        // same field find_order_id()'s third resolution path already
        // searches by by the time this fires.
        $txn_id = $order->get_transaction_id();
        if ( empty( $txn_id ) ) {
            return;
        }

        $transient_key = 'chargeguard_pending_enrich_paypal_' . $txn_id;
        $pending = get_transient( $transient_key );

        if ( $pending === false ) {
            return;
        }

        // Delete before the API call so a slow/failed send_enrich() can't
        // cause this to be reprocessed on a subsequent payment-complete
        // fire for the same order.
        delete_transient( $transient_key );

        $pending['orderId'] = (string) $order_id;

        // Re-resolve fresh from order meta — the queued payload's
        // deviceToken slot is always null at queue time (the order didn't
        // exist yet). By now _chargeguard_device_token, if any, is set.
        $meta_token = $order->get_meta( '_chargeguard_device_token' );
        $pending['deviceToken'] = ! empty( $meta_token ) ? $meta_token : null;

        $result = $this->api_client->send_enrich( $pending );

        if ( is_wp_error( $result ) ) {
            error_log( '[ChargeGuard] Deferred PayPal enrichment failed for order ' . $order_id . ': ' . $result->get_error_message() );
            return;
        }

        $refund_context = null;
        if ( ( $pending['eventType'] ?? null ) === 'PAYMENT.CAPTURE.COMPLETED' && ! empty( $pending['paypalTxnId'] ) ) {
            $refund_context = [
                'gateway'    => 'paypal',
                'capture_id' => $pending['paypalTxnId'],
            ];
        }

        $this->chargeguard_fire_device_fraud_hook( $result, $order_id, 'paypal_post_payment_block' );

        $this->chargeguard_maybe_block_order(
            $result,
            $order_id,
            __( 'Blocked by ChargeGuard: Suspicious PayPal payment detected.', 'chargeguard-woocommerce' ),
            $refund_context
        );
    }

    /**
     * التحقق من توقيع PayPal Webhook عبر Remote Verification API.
     *
     * @param WP_REST_Request $request الطلب الوارد.
     * @param string          $payload_raw الجسم الخام للطلب.
     * @return bool
     */
    private function verify_webhook_signature( $request, $payload_raw ) {
        $client_id     = get_option( 'chargeguard_paypal_client_id' );
        $client_secret = chargeguard_get_secret_option( 'chargeguard_paypal_client_secret' );
        $webhook_id    = get_option( 'chargeguard_paypal_webhook_id' );

        // Fail closed: incomplete PayPal credentials mean we cannot verify
        // this webhook's authenticity, so it must always be rejected.
        // There is no environment-based bypass — WP_DEBUG is a diagnostics
        // flag, not a trusted signal that this request originated from a
        // safe, non-public environment, and this endpoint is public.
        if ( ! $client_id || ! $client_secret || ! $webhook_id ) {
            return false;
        }

        // الحصول على Access Token (مخزّن في Transient لـ 8 ساعات)
        $access_token = $this->get_paypal_access_token( $client_id, $client_secret );
        if ( ! $access_token ) {
            return false;
        }

        $mode    = get_option( 'chargeguard_paypal_mode', 'sandbox' );
        $api_url = ( $mode === 'live' )
            ? 'https://api-m.paypal.com/v1/notifications/verify-webhook-signature'
            : 'https://api-m.sandbox.paypal.com/v1/notifications/verify-webhook-signature';

        $verify_body = [
            'auth_algo'         => $request->get_header( 'paypal_auth_algo' ),
            'cert_url'          => $request->get_header( 'paypal_cert_url' ),
            'transmission_id'   => $request->get_header( 'paypal_transmission_id' ),
            'transmission_sig'  => $request->get_header( 'paypal_transmission_sig' ),
            'transmission_time' => $request->get_header( 'paypal_transmission_time' ),
            'webhook_id'        => $webhook_id,
            'webhook_event'     => json_decode( $payload_raw, true ),
        ];

        $response = wp_remote_post( $api_url, [
            'timeout' => 10,
            'headers' => [
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $access_token,
            ],
            'body' => json_encode( $verify_body ),
        ] );

        if ( is_wp_error( $response ) ) {
            return false;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        return isset( $body['verification_status'] ) && $body['verification_status'] === 'SUCCESS';
    }

    /**
     * الحصول على PayPal Access Token مع caching.
     *
     * @param string $client_id
     * @param string $client_secret
     * @return string|null
     */
    private function get_paypal_access_token( $client_id, $client_secret ) {
        $cache_key = 'cg_paypal_access_token_' . md5( $client_id );
        $cached    = get_transient( $cache_key );
        if ( $cached ) {
            return $cached;
        }

        $mode    = get_option( 'chargeguard_paypal_mode', 'sandbox' );
        $api_url = ( $mode === 'live' )
            ? 'https://api-m.paypal.com/v1/oauth2/token'
            : 'https://api-m.sandbox.paypal.com/v1/oauth2/token';

        $response = wp_remote_post( $api_url, [
            'timeout' => 10,
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode( $client_id . ':' . $client_secret ),
                'Content-Type'  => 'application/x-www-form-urlencoded',
            ],
            'body' => 'grant_type=client_credentials',
        ] );

        if ( is_wp_error( $response ) ) {
            return null;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $body['access_token'] ) ) {
            return null;
        }

        // نخزن لـ 8 ساعات (PayPal token صالح لـ 9 ساعات)
        set_transient( $cache_key, $body['access_token'], 8 * HOUR_IN_SECONDS );
        return $body['access_token'];
    }

    /**
     * استخراج بيانات الدفع من PayPal payload.
     * يعالج كلاً من بطاقات الائتمان ومدفوعات PayPal Balance.
     *
     * @param array $payload
     * @return array|null
     */
    private function extract_payment_data( $payload ) {
        $resource = $payload['resource'] ?? null;
        if ( ! $resource ) {
            return null;
        }

        $extracted = [
            'txn_id'      => $resource['id'] ?? null,
            'payer_email' => null,
            'amount'      => null,
            'currency'    => null,
            'bin'         => null,
            'last4'       => null,
            'exp_month'   => null,
            'exp_year'    => null,
            'brand'       => null,
            'card_country'=> null,
            'funding'     => null,
        ];

        // ── استخراج بيانات البطاقة ───────────────────────────────────
        // المسار 1: payment_source.card (PayPal Advanced / Braintree)
        $card = $resource['payment_source']['card'] ?? null;
        if ( $card ) {
            // PayPal يرسل BIN في حقل bin أو أول 6 أرقام من number
            $extracted['bin']      = $card['bin'] ?? null;
            $extracted['last4']    = $card['last_digits'] ?? null;
            $extracted['brand']    = strtolower( $card['brand'] ?? '' ) ?: null;
            $extracted['funding']  = strtolower( $card['type'] ?? '' ) ?: null; // CREDIT/DEBIT

            // استخراج الشهر والسنة من expiry (صيغة: YYYY-MM)
            if ( ! empty( $card['expiry'] ) ) {
                $parts = explode( '-', $card['expiry'] );
                if ( count( $parts ) === 2 ) {
                    $extracted['exp_year']  = (int) $parts[0];
                    $extracted['exp_month'] = (int) $parts[1];
                }
            }

            // بعض استجابات PayPal تحتوي على billing_address.country_code
            $extracted['card_country'] = $card['billing_address']['country_code'] ?? null;
        }

        // المسار 2: payer.email_address (PayPal Balance أو أي دفع)
        $payer = $resource['payer'] ?? null;
        if ( $payer ) {
            $extracted['payer_email'] = $payer['email_address'] ?? null;
        }

        // المسار 3: amount
        $amount_data = $resource['amount'] ?? $resource['purchase_units'][0]['amount'] ?? null;
        if ( $amount_data ) {
            $extracted['amount']   = $amount_data['value'] ?? null;
            $extracted['currency'] = $amount_data['currency_code'] ?? null;
        }

        // إذا لم يكن هناك أي بيانات مفيدة، نتجاوز
        if ( ! $extracted['txn_id'] && ! $extracted['payer_email'] ) {
            return null;
        }

        return $extracted;
    }

    /**
     * البحث عن WooCommerce Order ID المرتبط بمعاملة PayPal.
     *
     * @param array $extracted البيانات المستخرجة.
     * @param array $payload   الـ payload الكامل.
     * @return int|null
     */
    private function find_order_id( $extracted, $payload ) {
        $resource = $payload['resource'] ?? [];

        // المسار 1: custom_id في purchase_units (WooCommerce يضع order_id هنا)
        $custom_id = $resource['purchase_units'][0]['custom_id']
                  ?? $resource['custom_id']
                  ?? null;
        if ( $custom_id && is_numeric( $custom_id ) ) {
            $order = wc_get_order( (int) $custom_id );
            if ( $order ) {
                return $order->get_id();
            }
        }

        // المسار 2: invoice_id
        $invoice_id = $resource['purchase_units'][0]['invoice_id'] ?? null;
        if ( $invoice_id && is_numeric( $invoice_id ) ) {
            $order = wc_get_order( (int) $invoice_id );
            if ( $order ) {
                return $order->get_id();
            }
        }

        // المسار 3: البحث بـ PayPal transaction ID في meta
        if ( ! empty( $extracted['txn_id'] ) ) {
            $orders = wc_get_orders( [
                'limit'      => 1,
                'meta_key'   => '_transaction_id',
                'meta_value' => $extracted['txn_id'],
                'return'     => 'ids',
            ] );
            if ( ! empty( $orders ) ) {
                return $orders[0];
            }
        }

        return null;
    }

    /**
     * توليد معرف افتراضي للمعاملات التي لم يُربط بها طلب WooCommerce.
     *
     * @param array $payload
     * @return string
     */
    private function generate_paypal_order_id( $payload ) {
        $txn_id = $payload['resource']['id'] ?? uniqid( 'pp_', true );
        return 'paypal_' . $txn_id;
    }

    /**
     * معالجة أحداث النزاعات لتغذية الـ Feedback Loop.
     *
     * @param array $payload
     */
    private function handle_dispute_event( $payload ) {
        $resource = $payload['resource'] ?? [];

        // Defense-in-depth: the $supported_events allow-list in
        // handle_webhook() should already guarantee only
        // CUSTOMER.DISPUTE.RESOLVED reaches this method, but that
        // event's own resource also carries a 'status' field — checking
        // it here costs nothing and protects against a future accidental
        // widening of the allow-list (e.g. someone adding
        // CUSTOMER.DISPUTE.UPDATED without re-reading this method).
        $status = $resource['status'] ?? null;
        if ( $status !== 'RESOLVED' ) {
            return true;
        }

        // The outcome only exists once resolved. Documented outcome_code
        // values:
        //   RESOLVED_BUYER_FAVOUR   — merchant lost. Confirmed loss.
        //   RESOLVED_SELLER_FAVOUR  — merchant won, claim rejected.
        //   RESOLVED_WITH_PAYOUT    — PayPal paid the buyer itself, not a
        //                             merchant loss.
        //   CANCELED_BY_BUYER / ACCEPTED / DENIED / NONE — other terminal
        //                             states, none a confirmed merchant loss.
        // Only RESOLVED_BUYER_FAVOUR may blacklist a device or send a
        // fraud=true signal.
        $outcome_code = $resource['dispute_outcome']['outcome_code'] ?? null;

        if ( $outcome_code !== 'RESOLVED_BUYER_FAVOUR' ) {
            // Merchant won, or some other non-loss outcome — do nothing.
            // Deterministic given this payload — safe to mark processed.
            return true;
        }

        $txn_id = $resource['disputed_transactions'][0]['seller_transaction_id'] ?? null;

        if ( ! $txn_id ) {
            return true;
        }

        // البحث عن الطلب المرتبط بهذه المعاملة
        $orders = wc_get_orders( [
            'limit'      => 1,
            'meta_key'   => '_transaction_id',
            'meta_value' => $txn_id,
            'return'     => 'ids',
        ] );

        if ( empty( $orders ) ) {
            // Deterministic — a redelivery carries the same txn_id and
            // will fail the same lookup, so mark processed rather than
            // let PayPal retry indefinitely.
            return true;
        }

        $order_id = $orders[0];

        // A confirmed RESOLVED_BUYER_FAVOUR loss is a confirmed-fraud
        // signal, not just a heuristic — activate the local firewall for
        // this device the same as any other definitive block decision.
        // Best-effort: does not gate the return value below.
        // Canonical accessor — see ChargeGuard_Dynamic_Firewall::get_order_device_fp()
        // for the read-both (canonical + legacy), write-one rationale.
        $device_fp = ChargeGuard_Dynamic_Firewall::get_order_device_fp( $order_id );
        if ( ! empty( $device_fp ) && $device_fp !== 'unknown' ) {
            do_action( 'chargeguard_mark_device_fraud', $device_fp, 'paypal_dispute_lost' );
        }

        // إرسال feedback للـ ChargeGuard Backend (isFraud = true) — only
        // ever reached now for a genuinely confirmed, resolved loss.
        //
        // Returns false on WP_Error so the caller withholds the
        // idempotency transient and returns non-2xx, letting PayPal's own
        // redelivery retry this confirmed fraud ruling instead of
        // silently dropping it — mirrors handle_dispute_closed() in
        // class-stripe-webhook.php. Safe to repeat: send_feedback() is
        // gated by the backend's own idempotency check on orderId, and
        // chargeguard_mark_device_fraud() above just re-overwrites the
        // same blacklist entry.
        $result = $this->api_client->send_feedback( $order_id, true );

        return ! is_wp_error( $result );
    }

    }