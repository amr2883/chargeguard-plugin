<?php
/**
 * ChargeGuard Stripe Webhook Handler
 *
 * يستقبل Webhook من Stripe، يستخرج BIN، ويرسله إلى ChargeGuard.
 *
 * @package ChargeGuard_WooCommerce
 */

class ChargeGuard_Stripe_Webhook {

    use ChargeGuard_Auto_Block_Trait;

    private $api_client;

    public function __construct() {
        $this->api_client = new ChargeGuard_API_Client();
        add_action('rest_api_init', [$this, 'register_rest_route']);

        // Consumes any enrichment data queued by handle_webhook() when the
        // Stripe webhook raced ahead of order creation. Hooked on payment
        // completion (rather than order creation) because that's the
        // earliest point a Stripe payment intent ID is reliably available
        // as order meta.
        add_action('woocommerce_payment_complete', [$this, 'consume_pending_enrichment']);
    }

    /**
     * تسجيل REST API endpoint لاستقبال Stripe Webhook.
     */
    public function register_rest_route() {
        register_rest_route('chargeguard/v1', '/stripe-webhook', [
            'methods'             => 'POST',
            'callback'            => [$this, 'handle_webhook'],
            'permission_callback' => '__return_true', // سيتم التحقق من توقيع Stripe داخل الدالة
        ]);
    }

    /**
     * معالجة Webhook Stripe الوارد.
     *
     * @param WP_REST_Request $request الطلب الوارد.
     * @return WP_REST_Response
     */
    public function handle_webhook($request) {
        // ── Confirm the integration is enabled ──────────────────────────
        // Mirrors the PayPal handler's pattern: if the merchant has
        // disabled (or never enabled, or disconnected) Stripe enrichment,
        // stop here before touching the Stripe SDK, verifying signatures,
        // or forwarding any card data downstream.
        if (get_option('chargeguard_stripe_enabled', '0') !== '1') {
            return new \WP_REST_Response(['status' => 'disabled'], 200);
        }

        $stripe_init = __DIR__ . '/../vendor/stripe-php/init.php';
        if (file_exists($stripe_init)) {
            require_once $stripe_init;
        } else {
            error_log('[ChargeGuard] Stripe webhook received but vendor/stripe-php/init.php is missing — run composer install.');
            return new \WP_REST_Response(['error' => 'Unable to process webhook'], 500);
        }

        // Must be set before any Stripe API call in this request (Charge::retrieve()
        // below requires it). constructEvent() itself only does a local signature
        // check and doesn't need the key, but setting it here fails fast if Stripe
        // hasn't been configured yet in the ChargeGuard settings page.
        $stripe_secret_key = chargeguard_get_secret_option('chargeguard_stripe_secret_key');
        if (!$stripe_secret_key) {
            error_log('[ChargeGuard] Stripe webhook received but no chargeguard_stripe_secret_key is configured.');
            return new \WP_REST_Response(['error' => 'Unable to process webhook'], 500);
        }
        \Stripe\Stripe::setApiKey($stripe_secret_key);

        $payload   = $request->get_body();
        $sig_header = $request->get_header('stripe_signature');
        $endpoint_secret = chargeguard_get_secret_option('chargeguard_stripe_webhook_secret');

        // التحقق من توقيع Stripe
        try {
            $event = \Stripe\Webhook::constructEvent($payload, $sig_header, $endpoint_secret);
        } catch (\Exception $e) {
            return new \WP_REST_Response(['error' => 'Invalid signature'], 403);
        }

        // ── فلترة الأحداث — نعالج فقط ما يهمنا ──────────────────
        // Allow-list mirrors ChargeGuard_PayPal_Webhook::handle_webhook().
        // charge.dispute.closed is subscribed — deliberately NOT
        // charge.dispute.created — for the same reason PayPal only
        // listens to CUSTOMER.DISPUTE.RESOLVED: .created fires the
        // instant a dispute is OPENED, before any outcome exists. Only
        // .closed's `status` field tells us whether the merchant lost.
        $supported_events = [
            'payment_intent.succeeded',
            'charge.dispute.closed',
        ];

        if (!in_array($event->type, $supported_events, true)) {
            return new \WP_REST_Response(['status' => 'ignored'], 200);
        }

        // ── Idempotency — منع معالجة نفس الحدث مرتين ────────────
        // Mirrors the PayPal handler's transient-based guard, keyed on
        // Stripe's own event ID (unique per delivery, and distinct
        // across event types, so this key scheme is safe to reuse here).
        $cache_key = 'cg_stripe_processed_' . md5($event->id);
        if (get_transient($cache_key)) {
            return new \WP_REST_Response(['status' => 'already_processed'], 200);
        }

        // Disputes are handled by a dedicated method with their own
        // resolution logic — dispatch and return here, before the
        // payment_intent-only code below (which assumes $event->data->object
        // is a PaymentIntent, not a Dispute).
        if ($event->type === 'charge.dispute.closed') {
            return $this->handle_dispute_closed($event, $cache_key);
        }

        // NOTE: the "processed" marker is intentionally NOT set here.
        // Stripe redelivers an event until it receives a 2xx response, and
        // that retry is exactly what we want for transient failures (a
        // network blip to the ChargeGuard backend, a slow/failing Stripe
        // API call). Marking the event as processed before we know the
        // outcome would cause every subsequent retry to be silently
        // swallowed by the already_processed check above, even though
        // nothing was actually enriched. The marker is set individually
        // below, only at points where processing has genuinely concluded
        // (successfully enriched, successfully queued as pending, or
        // failed for a reason a retry cannot fix) — never at points where
        // a retry could plausibly succeed.

        $payment_intent = $event->data->object;

        try {
            $charge = $this->get_latest_charge($payment_intent);
        } catch (\Exception $e) {
            error_log('[ChargeGuard] Stripe charge retrieval failed for ' . $payment_intent->id . ': ' . $e->getMessage());
            return new \WP_REST_Response(['error' => 'Charge retrieval failed'], 500);
        }

        if (!$charge) {
            // Deterministic given this event's payload — a retry will see
            // the same payment intent with no charges every time, so mark
            // processed to stop Stripe retrying a call that cannot succeed.
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['error' => 'No charges found'], 400);
        }

        $card = $charge->payment_method_details->card ?? null;

        if (!$card) {
            // Deterministic — the charge will never gain card details on
            // retry, so mark processed to stop further redelivery attempts.
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['error' => 'No card details found'], 400);
        }

        $iin     = $card->iin ?? null;
        $brand   = $card->brand ?? null;
        $country = $card->country ?? null;
        $funding = $card->funding ?? null;
        $last4   = $card->last4 ?? null;
        $expMonth = $card->exp_month ?? null;
        $expYear  = $card->exp_year ?? null;

        // Post-payment card-fingerprint signal (Layer 5 — see
        // src/lib/binSequenceDetector.js's checkCardFingerprintVelocity
        // and src/lib/enrichmentProcessor.js on the backend).
        // card->fingerprint is a Stripe-generated, non-reversible token
        // identifying the underlying physical card across payment
        // methods — it is NOT raw PAN data, so forwarding/storing it
        // does not expand PCI scope (same sensitivity tier as
        // deviceFingerprint, already sent today). wallet->type is
        // forwarded purely as forensic context — Apple Pay/Google Pay
        // produce a different fingerprint per device-token even for the
        // identical physical card, a documented limitation of this
        // layer, not a bug — it is never itself used in the velocity
        // decision.
        $card_fingerprint = $card->fingerprint ?? null;
        $card_wallet_type = $card->wallet->type ?? null;

        if (!$iin) {
            // Deterministic — the same card data will lack an IIN on retry too.
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['error' => 'No IIN found'], 400);
        }

        // البحث عن الطلب المرتبط بـ payment_intent_id
        $orders = wc_get_orders([
            'limit'       => 1,
            'meta_key'    => '_chargeguard_payment_intent_id',
            'meta_value'  => $payment_intent->id,
            'return'      => 'ids',
        ]);

        $order_id = !empty($orders) ? $orders[0] : $payment_intent->metadata->order_id ?? null;

        // If we resolved the order via the Stripe metadata fallback rather
        // than our own meta key, persist that meta now so future lookups
        // (including the deferred-enrichment consumer below) don't need to
        // rely on the fallback again.
        if ($order_id && empty($orders)) {
            $existing_order = wc_get_order($order_id);
            if ($existing_order && !$existing_order->get_meta('_chargeguard_payment_intent_id')) {
                $existing_order->update_meta_data('_chargeguard_payment_intent_id', $payment_intent->id);
                $existing_order->save_meta_data();
            }
        }

        // Threads the checkout-time device token through to this
        // post-payment enrichment call so /enrich can apply the same
        // deviceTrustFactor dampening /evaluate already applies pre-payment.
        // Absent for orders placed before this fix, on older plugin
        // versions, or when $order_id isn't resolved yet — deviceToken
        // stays null and /enrich falls back to deviceTrustFactor 1.0,
        // identical to today's behavior.
        $device_token = null;
        if ($order_id) {
            $order_for_token = wc_get_order($order_id);
            if ($order_for_token) {
                $meta_token = $order_for_token->get_meta('_chargeguard_device_token');
                $device_token = !empty($meta_token) ? $meta_token : null;
            }
        }

        if (!$order_id) {
            // تخزين مؤقت للبيانات حتى يصل Webhook الطلب
            set_transient('chargeguard_pending_enrich_' . $payment_intent->id, [
                'orderId'     => null,
                'paymentIntentId' => $payment_intent->id,
                'bin'         => $iin,
                'cardBrand'   => $brand,
                'cardCountry' => $country,
                'funding'     => $funding,
                'issuer'      => $charge->payment_method_details->card->issuer ?? null,
                'last4'       => $last4,
                'expMonth'    => $expMonth,
                'expYear'     => $expYear,
                'brand'       => $brand,
                'deviceToken' => $device_token,
                'cardFingerprint' => $card_fingerprint,
                'cardWalletType'  => $card_wallet_type,
            ], HOUR_IN_SECONDS);
            // Data is now safely persisted for the deferred consumer to
            // pick up — this delivery has concluded successfully, so mark
            // it processed now (not before, per the note above).
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['status' => 'pending', 'message' => 'Order not found, enrichment queued locally.'], 202);
        }

        // إرسال enrich إلى ChargeGuard
        $enrich_data = [
            'orderId'         => (string) $order_id,
            'paymentIntentId' => $payment_intent->id,
            'source'          => 'stripe',
            'bin'             => $iin,
            'cardBrand'       => $brand,
            'cardCountry'     => $country,
            'funding'         => $funding,
            'issuer'          => $charge->payment_method_details->card->issuer ?? null,
            'last4'           => $last4,
            'expMonth'        => $expMonth,
            'expYear'         => $expYear,
            'brand'           => $brand,
            'deviceToken'     => $device_token,
            'cardFingerprint' => $card_fingerprint,
            'cardWalletType'  => $card_wallet_type,
        ];

        $result = $this->api_client->send_enrich($enrich_data);

        if (is_wp_error($result)) {
            // Do NOT mark processed — this is exactly the transient-failure
            // case (network blip, backend 5xx) that Stripe's retry exists
            // for. Leaving the marker unset lets the next redelivery
            // attempt try send_enrich() again instead of being silently
            // swallowed by the already_processed check.
            return new \WP_REST_Response(['error' => $result->get_error_message()], 500);
        }

        // Enrichment succeeded — this delivery has genuinely concluded, so
        // mark it processed now.
        set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);

        // Activate the local firewall independently of whether auto-block is
        // enabled: blacklisting a device is a separate capability from
        // auto-cancelling this specific order, and shouldn't require the
        // merchant to have opted into auto-block just to get it.
        $this->chargeguard_fire_device_fraud_hook($result, $order_id, 'stripe_post_payment_block');

        // إذا كان القرار block، نقوم بإلغاء الطلب تلقائيًا إذا كان التاجر قد فعّل الميزة
        // (and, if chargeguard_auto_refund is separately enabled, refund it)
        $this->chargeguard_maybe_block_order(
            $result,
            $order_id,
            __('Blocked by ChargeGuard: Card Testing detected.', 'chargeguard-woocommerce'),
            [
                'gateway'           => 'stripe',
                'payment_intent_id' => $payment_intent->id,
            ]
        );

        return new \WP_REST_Response(['status' => 'enriched', 'result' => $result], 200);
    }

    /**
     * Consume any enrichment data queued by handle_webhook() for a Stripe
     * payment intent that arrived before its order existed.
     *
     * Fires on woocommerce_payment_complete rather than
     * woocommerce_checkout_order_created because the payment intent ID is
     * not reliably present as order meta at order-creation time — it's
     * written by the payment gateway (or by handle_webhook() itself, see
     * above) once payment has actually been processed.
     *
     * At-least-once semantics: if this fires more than once for the same
     * order (e.g. a payment-complete hook firing twice), the transient is
     * deleted on first consumption, so subsequent calls are safe no-ops.
     *
     * If the transient has already expired (1 hour TTL) or was never set
     * (the common case — most Stripe webhooks arrive after order
     * creation and are handled directly in handle_webhook()), this
     * silently returns; that is expected, not an error condition.
     *
     * @param int $order_id
     * @return void
     */
    public function consume_pending_enrichment($order_id) {
        $order = wc_get_order($order_id);
        if (!$order) {
            return;
        }

        $payment_intent_id = $order->get_meta('_chargeguard_payment_intent_id');

        // Fall back to common WooCommerce Stripe gateway meta keys — nothing
        // in ChargeGuard's own checkout flow writes this meta before the
        // gateway has actually created a payment intent, so on first pass
        // this key normally comes from the gateway itself.
        if (!$payment_intent_id) {
            $payment_intent_id = $order->get_meta('_stripe_intent_id')
                ?: $order->get_meta('_payment_intent_id')
                ?: $order->get_meta('_intent_id');

            if ($payment_intent_id) {
                $order->update_meta_data('_chargeguard_payment_intent_id', $payment_intent_id);
                $order->save_meta_data();
            }
        }

        if (!$payment_intent_id) {
            return;
        }

        $transient_key = 'chargeguard_pending_enrich_' . $payment_intent_id;
        $pending = get_transient($transient_key);

        if ($pending === false) {
            return;
        }

        // Delete before the API call so a slow/failed send_enrich() can't
        // cause this to be reprocessed on a subsequent payment-complete
        // fire for the same order.
        delete_transient($transient_key);

        $pending['orderId'] = (string) $order_id;

        // Re-resolve fresh from order meta — the queued payload's
        // deviceToken slot is always null at queue time (see
        // handle_webhook() above, where the order didn't exist yet). By
        // the time this fires (woocommerce_payment_complete) the order
        // exists and _chargeguard_device_token, if any, is set.
        $meta_token = $order->get_meta('_chargeguard_device_token');
        $pending['deviceToken'] = !empty($meta_token) ? $meta_token : null;

        $result = $this->api_client->send_enrich($pending);

        if (is_wp_error($result)) {
            error_log('[ChargeGuard] Deferred enrichment failed for order ' . $order_id . ': ' . $result->get_error_message());
            return;
        }

        $this->chargeguard_fire_device_fraud_hook($result, $order_id, 'stripe_post_payment_block');

        $this->chargeguard_maybe_block_order(
            $result,
            $order_id,
            __('Blocked by ChargeGuard: Card Testing detected.', 'chargeguard-woocommerce'),
            [
                'gateway'           => 'stripe',
                'payment_intent_id' => $payment_intent_id,
            ]
        );
    }

    /**
     * استرجاع كائن Charge الكامل من PaymentIntent، مع دعم للتوافق العكسي.
     *
     * Backward compatible: on older Stripe API versions the legacy
     * `charges.data` list may still be populated on the webhook payload
     * itself, so we prefer that (no extra API call) when present. On
     * newer API versions `charges` is absent/null and we fall back to
     * `latest_charge`, which webhook payloads only ever send as a bare
     * ID — Stripe does not auto-expand nested objects on event payloads,
     * so a separate retrieve() call is required to get payment_method_details.
     *
     * @param \Stripe\PaymentIntent $payment_intent
     * @return \Stripe\Charge|null
     * @throws \Stripe\Exception\ApiErrorException
     */
    private function get_latest_charge($payment_intent) {
        // Legacy path (older API versions): charges.data still populated inline.
        if (!empty($payment_intent->charges) && !empty($payment_intent->charges->data)) {
            return $payment_intent->charges->data[0];
        }

        // Current path: resolve latest_charge (ID only) via a separate API call.
        if (!empty($payment_intent->latest_charge)) {
            $charge_id = is_string($payment_intent->latest_charge)
                ? $payment_intent->latest_charge
                : $payment_intent->latest_charge->id;

            return \Stripe\Charge::retrieve($charge_id);
        }

        return null;
    }

    /**
     * معالجة حدث charge.dispute.closed لتغذية الـ Feedback Loop.
     *
     * Mirrors ChargeGuard_PayPal_Webhook::handle_dispute_event() — only a
     * confirmed loss may blacklist a device or report fraud=true.
     *
     * @param \Stripe\Event $event
     * @param string        $cache_key Idempotency key already computed by handle_webhook().
     * @return \WP_REST_Response
     */
    private function handle_dispute_closed($event, $cache_key) {
    $dispute = $event->data->object;
    $status  = $dispute->status ?? null;

    // [Learning-loop symmetry fix] 'warning_closed' لوحدها بلا قرار نهائي
    // مؤكد بتُتجاهل. 'won' دلوقتي بيُعالَج زي 'lost' (نفس نداء send_feedback،
    // isFraud=false) — قبل كده كان بيُتجاهل زي warning_closed، ومعناه إن
    // SignalStat كانت بتتغذى بخسائر فقط، فالـ lossRate لأي إشارة (شاملة
    // IP_TOR/IP_DATACENTER/BIN_PREPAID المستخدمة لكشف الكارد تيستنج) كانت
    // بتتجه بمرور الوقت لـ 1.0 بلا اعتبار لمعدل ظهورها الحقيقي في الأوردرات
    // الشرعية اللي كسبت نزاعاتها.
    if ($status !== 'lost' && $status !== 'won') {
        set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
        return new \WP_REST_Response(['status' => 'ignored', 'dispute_status' => $status], 200);
    }

        $order_id = $this->find_order_id_for_dispute($dispute);

        if (!$order_id) {
            // Also deterministic: a redelivery carries the same
            // payment_intent/charge IDs and will fail the same lookup, so
            // mark processed and log for manual follow-up rather than let
            // Stripe retry a match that cannot succeed.
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            error_log('[ChargeGuard] Stripe dispute ' . $dispute->id . ' closed as lost, but no matching order was found (payment_intent: ' . ($dispute->payment_intent ?? 'none') . ', charge: ' . ($dispute->charge ?? 'none') . ').');
            return new \WP_REST_Response(['status' => 'order_not_found'], 200);
        }

        // Best-effort, does not gate the idempotency marker or response
        // below — the send_feedback() call further down is the
        // higher-value signal and must not be blocked by this step.
        // Canonical accessor — see ChargeGuard_Dynamic_Firewall::get_order_device_fp()
        // for the read-both (canonical + legacy), write-one rationale.
        $is_fraud = ($status === 'lost');

        if ($is_fraud) {
            $device_fp = ChargeGuard_Dynamic_Firewall::get_order_device_fp($order_id);
            if (!empty($device_fp) && $device_fp !== 'unknown') {
                do_action('chargeguard_mark_device_fraud', $device_fp, 'stripe_dispute_lost');
            }
        }
        // isFraud=false هنا هي الإصلاح — كانت مفيش خالص قبل كده، يعني كل
        // نزاع كسبه التاجر كان بيتفوّت 100% من SignalStat (صفر تسجيل، مش
        // حتى "خسارة صفرية").
        $result = $this->api_client->send_feedback($order_id, $is_fraud);

        if (is_wp_error($result)) {
            // Do NOT mark processed. A confirmed 'lost' dispute is a
            // financial institution's final fraud ruling — losing it to
            // a transient backend failure (or an open circuit breaker) is
            // strictly worse than losing a BIN-enrichment row, and Stripe
            // already retries non-2xx webhook responses for up to several
            // days. Returning 500 lets that redelivery retry
            // send_feedback() later instead of silently dropping a
            // ground-truth fraud label. Safe to repeat on redelivery:
            // chargeguard_mark_device_fraud() above idempotently
            // overwrites the same blacklist entry, and the backend's
            // feedback endpoint has its own idempotency gate on orderId.
            error_log('[ChargeGuard] send_feedback failed for order ' . $order_id . ' (Stripe dispute ' . $dispute->id . '), code: ' . $result->get_error_code() . ', message: ' . $result->get_error_message() . ' — returning 500 for Stripe redelivery.');
            return new \WP_REST_Response(['error' => 'send_feedback failed'], 500);
        }

        // Confirmed success — this delivery has genuinely concluded.
        set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);

        return new \WP_REST_Response(['status' => 'handled', 'order_id' => $order_id], 200);
    }

    /**
     * البحث عن WooCommerce Order ID المرتبط بنزاع Stripe.
     *
     * Tries payment_intent first against the _chargeguard_payment_intent_id
     * meta key already populated for payment_intent.succeeded (no new meta
     * key needed). Falls back to charge ID against _transaction_id,
     * matching the pattern already used elsewhere in this plugin.
     *
     * @param \Stripe\Dispute $dispute
     * @return int|null
     */
    private function find_order_id_for_dispute($dispute) {
        $payment_intent_id = is_string($dispute->payment_intent ?? null)
            ? $dispute->payment_intent
            : ($dispute->payment_intent->id ?? null);

        if ($payment_intent_id) {
            $orders = wc_get_orders([
                'limit'      => 1,
                'meta_key'   => '_chargeguard_payment_intent_id',
                'meta_value' => $payment_intent_id,
                'return'     => 'ids',
            ]);
            if (!empty($orders)) {
                return $orders[0];
            }
        }

        $charge_id = is_string($dispute->charge ?? null)
            ? $dispute->charge
            : ($dispute->charge->id ?? null);

        if ($charge_id) {
            $orders = wc_get_orders([
                'limit'      => 1,
                'meta_key'   => '_transaction_id',
                'meta_value' => $charge_id,
                'return'     => 'ids',
            ]);
            if (!empty($orders)) {
                return $orders[0];
            }
        }

        return null;
    }

    }