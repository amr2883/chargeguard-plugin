// v1.1 draft — pending rewrite using onCheckoutValidation + IntegrationInterface.
// Do NOT wire up as-is; contains known re-entrancy bug and unstable internal API usage.
/**
 * ChargeGuard - Checkout Block Interceptor
 *
 * Architecture
 * ────────────
 * This script provides CLIENT-SIDE pre-flight fraud detection for the
 * WooCommerce Checkout Block. It is DEFENCE-IN-DEPTH — the authoritative
 * block happens server-side inside intercept_blocks_checkout() via
 * woocommerce_store_api_checkout_order_validation.
 *
 * Why two layers?
 *   • Server layer  → cannot be bypassed; blocks order creation in the DB
 *   • Client layer  → faster UX; shows an error before the Store API is
 *                     even called, saving a round-trip for obvious fraud
 *
 * How the client layer works
 * ──────────────────────────
 * The WooCommerce Checkout Block exposes a data store at 'wc/store/checkout'.
 * We subscribe to store changes and watch for the 'isBeforeProcessing' state.
 * When it becomes true (user clicked "Place Order") we:
 *   1. Immediately dispatch __internalSetProcessing(false) to pause the flow
 *   2. Call our /chargeguard/v1/evaluate REST endpoint
 *   3a. If decision === 'block': inject a validation error via
 *       'wc/store/validation' — Blocks renders it automatically
 *   3b. If decision !== 'block': release the pause so Blocks continues
 *   3c. If API call fails: release the pause (fail open)
 *
 * Critical constraints
 * ────────────────────
 * • We MUST NOT use undocumented internal actions like __internalSetAfterProcessing
 *   with arbitrary payloads — they have changed between WC versions.
 * • The 'wc/store/validation' store is the correct public API for surfacing
 *   inline errors inside the Block checkout UI (WC 7.6+).
 * • We guard against re-entrancy: once a check is in-flight, we ignore
 *   subsequent isBeforeProcessing signals until it resolves.
 *
 * @package ChargeGuard_WooCommerce
 */
(function () {
    'use strict';

    // ──────────────────────────────────────────────────────────────────────────
    // Config (injected via wp_localize_script as `chargeguard_block`)
    // ──────────────────────────────────────────────────────────────────────────
    // chargeguard_block.evaluate_url  : string  REST endpoint
    // chargeguard_block.rest_nonce    : string  wp_rest nonce
    // chargeguard_block.messages      : object  { blocked, api_error }

    var VALIDATION_KEY = 'chargeguard-fraud-check';

    // ──────────────────────────────────────────────────────────────────────────
    // Initialisation — wait for wp.data AND wc/store/checkout to be ready
    // ──────────────────────────────────────────────────────────────────────────

    var attempts    = 0;
    var MAX_WAIT_MS = 10000; // give up after 10 s (page load is long over by then)
    var INTERVAL_MS = 100;

    function waitForDeps() {
        attempts++;

        if (
            typeof window.wp                        !== 'undefined' &&
            typeof window.wp.data                   !== 'undefined' &&
            typeof window.wp.data.select            === 'function'  &&
            window.wp.data.select('wc/store/checkout') !== null
        ) {
            init();
            return;
        }

        if (attempts * INTERVAL_MS < MAX_WAIT_MS) {
            setTimeout(waitForDeps, INTERVAL_MS);
        } else {
            // The Block checkout store never became available — either this is a
            // Classic Checkout page or something went wrong. Either way, the
            // server-side guard is still active, so this is non-critical.
            console.warn('[ChargeGuard] Checkout block store not found — client-side pre-flight disabled.');
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Core logic
    // ──────────────────────────────────────────────────────────────────────────

    function init() {
        var wpData = window.wp.data;

        // Selectors
        var checkoutStore   = wpData.select('wc/store/checkout');
        var cartStore       = wpData.select('wc/store/cart');
        var validationStore = wpData.select('wc/store/validation');

        // Dispatchers (resolved once so we don't call select on every tick)
        var dispatchCheckout   = wpData.dispatch('wc/store/checkout');
        var dispatchValidation = wpData.dispatch('wc/store/validation');

        // Guard: some stores may not be present (e.g. on non-checkout pages)
        if (!checkoutStore || !cartStore || !validationStore) {
            console.warn('[ChargeGuard] Required WC stores not available.');
            return;
        }

        // State flags
        var isChecking        = false;  // prevent re-entrant calls
        var lastEmailChecked  = '';     // avoid repeating the same check

        wpData.subscribe(function () {
            // ── Gate 1: only act during the "before processing" window ──────
            if (!checkoutStore.isBeforeProcessing()) {
                return;
            }

            // ── Gate 2: prevent concurrent checks ───────────────────────────
            if (isChecking) {
                return;
            }

            // ── Collect order data from the cart/checkout stores ────────────
            //
            // getBillingAddress() is the stable API (WC 8.0+).
            // Fall back to the legacy getBillingData() for older versions.
            var billingAddress = (
                typeof checkoutStore.getBillingAddress === 'function'
                    ? checkoutStore.getBillingAddress()
                    : (typeof checkoutStore.getBillingData === 'function' ? checkoutStore.getBillingData() : {})
            ) || {};

            var email          = billingAddress.email   || '';
            var billingCountry = billingAddress.country || '';

            // Cart totals — getCartData().totals.total_price is in minor units
            var cartData = (typeof cartStore.getCartData === 'function') ? cartStore.getCartData() : {};
            var totals   = cartData.totals || {};
            // total_price is a string in minor units (e.g. "5000" = $50.00)
            var amount   = totals.total_price ? (parseInt(totals.total_price, 10) / 100) : 0;

            // ── Gate 3: require an email address ────────────────────────────
            if (!email) {
                return;
            }

            // ── Gate 4: skip if same email was already evaluated and passed ─
            if (email === lastEmailChecked) {
                return;
            }

            // ── Pause the checkout flow ──────────────────────────────────────
            //
            // __internalSetProcessing(false) tells the Blocks runtime to stay
            // in the "before processing" state while we do our async check.
            // This is the documented internal action for extending checkout in
            // WC Blocks; it is used by the payment method integrations too.
            isChecking = true;
            if (typeof dispatchCheckout.__internalSetProcessing === 'function') {
                dispatchCheckout.__internalSetProcessing(false);
            }

            // Clear any previous ChargeGuard validation error before re-checking
            if (typeof dispatchValidation.clearValidationError === 'function') {
                dispatchValidation.clearValidationError(VALIDATION_KEY);
            }

            // ── Call the pre-flight REST endpoint ───────────────────────────
            fetch(chargeguard_block.evaluate_url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce':   chargeguard_block.rest_nonce,
                },
                body: JSON.stringify({
                    email:           email,
                    amount:          amount,
                    billing_country: billingCountry,
                }),
                credentials: 'same-origin',
            })
            .then(function (response) {
                return response.json();
            })
            .then(function (data) {
                isChecking = false;

                if (data && data.decision === 'block') {
                    // ── BLOCKED ──────────────────────────────────────────────
                    //
                    // Inject a validation error into the Blocks validation store.
                    // The Checkout Block UI automatically renders validation errors
                    // keyed by VALIDATION_KEY — no custom component needed.
                    if (typeof dispatchValidation.setValidationErrors === 'function') {
                        dispatchValidation.setValidationErrors({
                            [VALIDATION_KEY]: {
                                message: chargeguard_block.messages.blocked,
                                hidden:  false,
                            },
                        });
                    }

                    // Signal that checkout cannot proceed
                    if (typeof dispatchCheckout.__internalSetHasError === 'function') {
                        dispatchCheckout.__internalSetHasError(true);
                    }

                    // Do NOT update lastEmailChecked — if the user changes email
                    // we should re-evaluate
                } else {
                    // ── ALLOWED ──────────────────────────────────────────────
                    lastEmailChecked = email;

                    // Resume normal checkout processing
                    if (typeof dispatchCheckout.__internalSetProcessing === 'function') {
                        dispatchCheckout.__internalSetProcessing(true);
                    }
                }
            })
            .catch(function (error) {
                // ── API FAILURE — fail open ──────────────────────────────────
                //
                // We never block on a network/API error. The server-side guard
                // is the authoritative control.
                console.warn('[ChargeGuard] Pre-flight API error — failing open:', error);
                isChecking = false;
                lastEmailChecked = email; // don't retry on API errors

                // Resume checkout
                if (typeof dispatchCheckout.__internalSetProcessing === 'function') {
                    dispatchCheckout.__internalSetProcessing(true);
                }
            });
        });

        console.log('[ChargeGuard] Checkout block interceptor active.');
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Entry point
    // ──────────────────────────────────────────────────────────────────────────

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', waitForDeps);
    } else {
        // DOMContentLoaded already fired
        waitForDeps();
    }

}());