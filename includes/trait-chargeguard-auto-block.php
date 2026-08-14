<?php
/**
 * Shared auto-block logic for ChargeGuard webhook handlers.
 *
 * Used by both the Stripe and PayPal webhook handlers so the
 * auto-block decision logic exists in exactly one place.
 *
 * @package ChargeGuard_WooCommerce
 */

trait ChargeGuard_Auto_Block_Trait {

    /**
     * Fail the order automatically if the ChargeGuard decision is "block"
     * and the merchant has explicitly enabled auto-block. If the merchant
     * has ALSO opted into the separate, more dangerous chargeguard_auto_refund
     * setting, attempt a real gateway refund after the status change
     * succeeds.
     *
     * IMPORTANT: marking the order "failed" does NOT by itself refund the
     * payment — that only happens if chargeguard_auto_refund is separately
     * enabled AND $refund_context is supplied by the caller. See admin
     * settings warning.
     *
     * @param array      $result         Enrich result from ChargeGuard.
     * @param int        $order_id       WooCommerce order ID.
     * @param string     $reason         Order-note / status-change reason, gateway-specific.
     * @param array|null $refund_context Optional. Enables the auto-refund path for
     *                                   this call. Shape:
     *                                     [ 'gateway' => 'stripe'|'paypal',
     *                                       'payment_intent_id' => string|null, // Stripe
     *                                       'capture_id' => string|null ]       // PayPal
     *                                   If omitted, auto-refund is never attempted for
     *                                   this call regardless of the merchant's setting —
     *                                   existing/future callers that don't pass this
     *                                   behave exactly as before this change.
     */
    /**
     * Fires chargeguard_mark_device_fraud for a post-payment block decision,
     * independently of the chargeguard_auto_block setting — blacklisting a
     * device at the local-firewall level is a distinct capability from
     * auto-cancelling this particular order, and shouldn't be gated behind
     * a setting the merchant may not have enabled.
     *
     * @param array  $result   Enrich/webhook result from ChargeGuard.
     * @param int    $order_id WooCommerce order ID.
     * @param string $reason   Passed through as the hook's $reason arg.
     */
    private function chargeguard_fire_device_fraud_hook( $result, $order_id, $reason ) {
        $decision = strtolower( $result['newDecision'] ?? $result['decision'] ?? '' );
        if ( $decision !== 'block' || empty( $order_id ) ) {
            return;
        }

        // Canonical accessor — see ChargeGuard_Dynamic_Firewall::get_order_device_fp()
        // for the read-both (canonical + legacy), write-one rationale.
        $device_fp = ChargeGuard_Dynamic_Firewall::get_order_device_fp( $order_id );
        if ( empty( $device_fp ) || $device_fp === 'unknown' ) {
            return;
        }

        do_action( 'chargeguard_mark_device_fraud', $device_fp, $reason );
    }

    private function chargeguard_maybe_block_order( $result, $order_id, $reason = '', $refund_context = null ) {
        $auto_block = get_option( 'chargeguard_auto_block', 'no' );
        if ( $auto_block !== 'yes' ) {
            return;
        }

        $decision = $result['newDecision'] ?? $result['decision'] ?? '';
        if ( strtolower( $decision ) !== 'block' ) {
            return;
        }

        $order = wc_get_order( $order_id );
        if ( ! $order ) {
            return;
        }

        // Idempotency guard: if this order was already marked failed by a
        // previous call, skip re-applying the status transition and note —
        // but still fall through to the refund check below, since a prior
        // call may have blocked-but-not-yet-refunded (e.g. a transient
        // refund API error on an earlier delivery).
        $already_failed = $order->has_status( 'failed' );

        if ( ! $already_failed ) {
            $min_amount = (float) get_option( 'chargeguard_block_min_amount', 0 );
            if ( $min_amount > 0 && $order->get_total() < $min_amount ) {
                return;
            }

            if ( '' === $reason ) {
                $reason = __( 'Blocked by ChargeGuard: fraud decision received.', 'chargeguard-woocommerce' );
            }

            $order->update_status( 'failed', $reason );
            $order->add_order_note( 'ChargeGuard decision: block. Flags: ' . json_encode( $result['flags'] ?? [] ) );
        }

        // ── Auto-Refund (opt-in, separate from Auto-Block) ────────────────
        // Only reachable when the merchant enabled BOTH chargeguard_auto_block
        // (checked above) AND chargeguard_auto_refund, and the calling
        // webhook handler supplied identifying payment data.
        if ( $refund_context && get_option( 'chargeguard_auto_refund', 'no' ) === 'yes' ) {
            $this->chargeguard_execute_auto_refund( $order, $refund_context );
        }
    }

    /**
     * Executes the gateway-side refund. Never throws — every failure path
     * is caught, logged (error_log + order note), and returns false, so a
     * refund failure can never turn an already-successful enrichment call
     * into a webhook 5xx (which would trigger a redundant retry).
     *
     * @param \WC_Order $order
     * @param array     $refund_context See chargeguard_maybe_block_order() docblock.
     * @return bool True if a refund was issued, or was already present (idempotent no-op).
     */
    private function chargeguard_execute_auto_refund( $order, $refund_context ) {
        // Idempotency guard — set the moment a refund is confirmed
        // successful below; checked first so a duplicate webhook delivery
        // (both Stripe and PayPal redeliver aggressively) can never
        // double-refund the same order.
        if ( $order->get_meta( '_chargeguard_auto_refund_id' ) ) {
            return true;
        }

        $gateway = $refund_context['gateway'] ?? '';

        if ( $gateway === 'stripe' ) {
            return $this->chargeguard_refund_stripe( $order, $refund_context['payment_intent_id'] ?? null );
        }

        if ( $gateway === 'paypal' ) {
            return $this->chargeguard_refund_paypal( $order, $refund_context['capture_id'] ?? null );
        }

        error_log( '[ChargeGuard] Auto-refund requested with unknown gateway "' . $gateway . '" for order ' . $order->get_id() );
        $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: unknown payment gateway context.', 'chargeguard-woocommerce' ) );
        return false;
    }

    /**
     * @param \WC_Order   $order
     * @param string|null $payment_intent_id
     * @return bool
     */
    private function chargeguard_refund_stripe( $order, $payment_intent_id ) {
        if ( ! $payment_intent_id ) {
            error_log( '[ChargeGuard] Auto-refund: missing Stripe payment_intent_id for order ' . $order->get_id() );
            $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: no Stripe payment intent ID available.', 'chargeguard-woocommerce' ) );
            return false;
        }

        // Defensive re-init: safe to call from any context regardless of
        // whether the Stripe SDK was already loaded/keyed earlier in this
        // request (it always is, on the real Stripe webhook path).
        if ( ! class_exists( '\Stripe\Refund' ) ) {
            $stripe_init = __DIR__ . '/../vendor/stripe-php/init.php';
            if ( ! file_exists( $stripe_init ) ) {
                error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ': Stripe SDK not installed.' );
                $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: Stripe SDK not installed.', 'chargeguard-woocommerce' ) );
                return false;
            }
            require_once $stripe_init;
        }

        $secret_key = chargeguard_get_secret_option( 'chargeguard_stripe_secret_key' );
        if ( ! $secret_key ) {
            error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ': no Stripe secret key configured.' );
            $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: no Stripe secret key configured.', 'chargeguard-woocommerce' ) );
            return false;
        }
        \Stripe\Stripe::setApiKey( $secret_key );

        try {
            $refund = \Stripe\Refund::create( [
                'payment_intent' => $payment_intent_id,
                'reason'         => 'fraudulent',
            ] );

            $order->update_meta_data( '_chargeguard_auto_refund_id', $refund->id );
            $order->save_meta_data();
            $order->add_order_note( sprintf(
                /* translators: %s: Stripe refund ID */
                __( 'ChargeGuard auto-refund: Stripe refund %s issued automatically after a post-payment block decision.', 'chargeguard-woocommerce' ),
                $refund->id
            ) );
            return true;

        } catch ( \Stripe\Exception\InvalidRequestException $e ) {
            $stripe_code = method_exists( $e, 'getStripeCode' ) ? $e->getStripeCode() : null;
            if ( $stripe_code === 'charge_already_refunded' ) {
                $order->update_meta_data( '_chargeguard_auto_refund_id', 'already_refunded' );
                $order->save_meta_data();
                $order->add_order_note( __( 'ChargeGuard auto-refund: payment was already refunded on Stripe (no action taken).', 'chargeguard-woocommerce' ) );
                return true;
            }

            error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ' (Stripe): ' . $e->getMessage() );
            $order->add_order_note( sprintf(
                /* translators: %s: error message from Stripe */
                __( 'ChargeGuard auto-refund FAILED (Stripe): %s. Manual refund review required.', 'chargeguard-woocommerce' ),
                $e->getMessage()
            ) );
            return false;

        } catch ( \Exception $e ) {
            error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ' (Stripe, unexpected): ' . $e->getMessage() );
            $order->add_order_note( sprintf(
                __( 'ChargeGuard auto-refund FAILED (Stripe, unexpected error): %s. Manual refund review required.', 'chargeguard-woocommerce' ),
                $e->getMessage()
            ) );
            return false;
        }
    }

    /**
     * @param \WC_Order   $order
     * @param string|null $capture_id
     * @return bool
     */
    private function chargeguard_refund_paypal( $order, $capture_id ) {
        if ( ! $capture_id ) {
            error_log( '[ChargeGuard] Auto-refund: missing PayPal capture_id for order ' . $order->get_id() );
            $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: no PayPal capture ID available.', 'chargeguard-woocommerce' ) );
            return false;
        }

        $client_id     = get_option( 'chargeguard_paypal_client_id' );
        $client_secret = chargeguard_get_secret_option( 'chargeguard_paypal_client_secret' );
        if ( ! $client_id || ! $client_secret ) {
            error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ': no PayPal credentials configured.' );
            $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: no PayPal credentials configured.', 'chargeguard-woocommerce' ) );
            return false;
        }

        // get_paypal_access_token() is defined on ChargeGuard_PayPal_Webhook
        // itself, not on this trait. This branch is only ever reached when
        // $this is that class (gateway === 'paypal' is only ever passed
        // from class-paypal-webhook.php) — checked explicitly rather than
        // assumed, so a future rename there fails loudly here instead of fataling.
        if ( ! method_exists( $this, 'get_paypal_access_token' ) ) {
            error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ': PayPal access-token helper unavailable in this context.' );
            $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: internal PayPal auth helper unavailable.', 'chargeguard-woocommerce' ) );
            return false;
        }

        $access_token = $this->get_paypal_access_token( $client_id, $client_secret );
        if ( ! $access_token ) {
            error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ': could not obtain PayPal access token.' );
            $order->add_order_note( __( 'ChargeGuard auto-refund FAILED: could not authenticate with PayPal.', 'chargeguard-woocommerce' ) );
            return false;
        }

        $mode    = get_option( 'chargeguard_paypal_mode', 'sandbox' );
        $api_url = ( $mode === 'live' )
            ? 'https://api-m.paypal.com/v2/payments/captures/' . rawurlencode( $capture_id ) . '/refund'
            : 'https://api-m.sandbox.paypal.com/v2/payments/captures/' . rawurlencode( $capture_id ) . '/refund';

        $response = wp_remote_post( $api_url, [
            'timeout' => 15,
            'headers' => [
                'Content-Type'       => 'application/json',
                'Authorization'      => 'Bearer ' . $access_token,
                'PayPal-Request-Id'  => 'cg-refund-' . $order->get_id(), // PayPal-side idempotency key
            ],
            'body' => json_encode( [
                'note_to_payer' => __( 'Refunded automatically: suspicious card-testing activity detected.', 'chargeguard-woocommerce' ),
            ] ),
        ] );

        if ( is_wp_error( $response ) ) {
            error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ' (PayPal network error): ' . $response->get_error_message() );
            $order->add_order_note( sprintf(
                __( 'ChargeGuard auto-refund FAILED (PayPal network error): %s. Manual refund review required.', 'chargeguard-woocommerce' ),
                $response->get_error_message()
            ) );
            return false;
        }

        $code = wp_remote_retrieve_response_code( $response );
        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( in_array( $code, [ 200, 201 ], true ) && ! empty( $body['id'] ) ) {
            $order->update_meta_data( '_chargeguard_auto_refund_id', $body['id'] );
            $order->save_meta_data();
            $order->add_order_note( sprintf(
                /* translators: %s: PayPal refund ID */
                __( 'ChargeGuard auto-refund: PayPal refund %s issued automatically after a post-payment block decision.', 'chargeguard-woocommerce' ),
                $body['id']
            ) );
            return true;
        }

        // Already-refunded conflict: PayPal returns 422 with
        // details[].issue === CAPTURE_FULLY_REFUNDED.
        $issue = $body['details'][0]['issue'] ?? '';
        if ( $code === 422 && $issue === 'CAPTURE_FULLY_REFUNDED' ) {
            $order->update_meta_data( '_chargeguard_auto_refund_id', 'already_refunded' );
            $order->save_meta_data();
            $order->add_order_note( __( 'ChargeGuard auto-refund: capture was already fully refunded on PayPal (no action taken).', 'chargeguard-woocommerce' ) );
            return true;
        }

        $error_message = $body['message'] ?? ( 'HTTP ' . $code );
        error_log( '[ChargeGuard] Auto-refund FAILED for order ' . $order->get_id() . ' (PayPal, ' . $code . '): ' . $error_message );
        $order->add_order_note( sprintf(
            __( 'ChargeGuard auto-refund FAILED (PayPal): %s. Manual refund review required.', 'chargeguard-woocommerce' ),
            $error_message
        ) );
        return false;
    }
}