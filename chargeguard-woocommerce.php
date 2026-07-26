<?php
/**
 * Plugin Name: ChargeGuard for WooCommerce
 * Description: Advanced Card Testing prevention powered by ChargeGuard intelligence.
 * Version:     1.0.0
 * Author:      ChargeGuard
 * Author URI:  https://chargeguard.io
 * License:     GPLv2 or later
 * Text Domain: chargeguard-woocommerce
 */

defined('ABSPATH') || exit;

/**
 * Single source of truth for the plugin's version, read directly from
 * the header comment above so it can never drift out of sync with the
 * `Version:` line. Used to cache-bust every enqueued script/style â€”
 * bumping the header version alone is enough to invalidate cached
 * assets on the next release, with no separate literal to remember to
 * update. Mirrors WordPress core's own convention (WP_VERSION,
 * WC_VERSION).
 */
if (!defined('CHARGEGUARD_VERSION')) {
    $chargeguard_plugin_data = get_file_data(__FILE__, ['Version' => 'Version']);
    define('CHARGEGUARD_VERSION', $chargeguard_plugin_data['Version']);
    unset($chargeguard_plugin_data);
}

/**
 * Cloudflare Turnstile site key used on the Connect flow (see
 * ChargeGuard_Admin_Settings::settings_page()). This is a PUBLIC value â€”
 * safe to ship in HTML â€” unlike chargeguard_api_key / webhook/signing
 * secrets, which are encrypted at rest via ChargeGuard_Secret_Crypto.
 *
 * It is intentionally NOT hardcoded here: Cloudflare issues a distinct
 * site key per registered site/environment (local, staging, production),
 * so the value must be overridable without touching plugin source.
 *
 * Override by adding this line to wp-config.php (above the
 * "That's all, stop editing!" comment):
 *   define('CHARGEGUARD_TURNSTILE_SITE_KEY', 'your_real_site_key_here');
 *
 * The default below is Cloudflare's published "always passes" test key,
 * so the Connect flow still functions on a fresh install before an
 * environment-specific key is configured. Replace it before go-live.
 * https://developers.cloudflare.com/turnstile/troubleshooting/testing/
 */
if (!defined('CHARGEGUARD_TURNSTILE_SITE_KEY')) {
    define('CHARGEGUARD_TURNSTILE_SITE_KEY', apply_filters('chargeguard_turnstile_site_key', '1x00000000000000000000AA'));
}

/**
 * Optional: a dedicated encryption key for ChargeGuard's at-rest secret
 * storage (Stripe/PayPal/API credentials), used in place of
 * wp_salt('auth') when defined. This keeps the encryption key outside
 * the database on hosts that never hardcode AUTH_KEY/AUTH_SALT in
 * wp-config.php. See ChargeGuard_Secret_Crypto::get_key().
 *
 * ChargeGuard never defines this itself â€” it must be set by the
 * merchant/host as a 64-character random hex string, e.g. via:
 *   define('CHARGEGUARD_ENCRYPTION_KEY', 'REPLACE_WITH_64_HEX_CHARS');
 * in wp-config.php (above "That's all, stop editing!"), or by exporting
 * it as an OS environment variable and reading it into a constant.
 * Generate one with: bin2hex(random_bytes(32))
 */

require_once __DIR__ . '/includes/class-api-client.php';
require_once __DIR__ . '/includes/trait-chargeguard-auto-block.php';
require_once __DIR__ . '/includes/class-admin-settings.php';
require_once __DIR__ . '/includes/class-stripe-webhook.php';
require_once __DIR__ . '/includes/class-paypal-webhook.php';
require_once __DIR__ . '/includes/class-trusted-proxy.php';
require_once __DIR__ . '/includes/class-dynamic-firewall.php';

require_once __DIR__ . '/includes/class-privacy.php';
require_once __DIR__ . '/includes/class-plugin-updater.php';

/**
 * Declare compatibility with WooCommerce's High-Performance Order Storage
 * (custom order tables). Must run on before_woocommerce_init â€” the hook
 * WooCommerce itself fires specifically for this declaration, ahead of
 * plugins_loaded (where chargeguard_init() runs) â€” so this registration
 * is intentionally separate from and earlier than the rest of this file's
 * bootstrap logic.
 */
add_action('before_woocommerce_init', function () {
    if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});

// chargeguard_add_device_fingerprint_to_order() removed — its sole
// purpose was writing the now-deprecated `_chargeguard_device_fingerprint`
// meta key on woocommerce_checkout_create_order. That hook only fires for
// classic checkout (Blocks/Store API checkout builds its order via a
// separate code path and doesn't reliably fire it), which meant this
// function silently never ran for Blocks-checkout orders — exactly the
// kind of two-key drift this unification removes. `_chargeguard_device_fp`
// (written by ChargeGuard_Dynamic_Firewall::intercept_checkout_block() and
// reconcile_pre_order_id()) already covers both checkout flows and is now
// the single canonical key; see get_order_device_fp() there for the
// read-both, write-one transitional strategy.

if (!function_exists('chargeguard_add_fingerprint_to_webhook_payload')) {
    function chargeguard_add_fingerprint_to_webhook_payload($payload, $resource, $resource_id, $webhook_id) {
        // Only enrich the payload for the webhook ChargeGuard itself created.
        // Without this check, the fingerprint leaks into every other webhook
        // the merchant has configured (Zapier, ERP, shipping, etc.).
        $chargeguard_webhook_id = (int) get_option('chargeguard_webhook_id');
        if (!$chargeguard_webhook_id || (int) $webhook_id !== $chargeguard_webhook_id) {
            return $payload;
        }

        if ($resource === 'order' && isset($payload['id'])) {
            // Canonical accessor — see ChargeGuard_Dynamic_Firewall::get_order_device_fp()
            // for the read-both (canonical + legacy), write-one rationale.
            // This also fixes a live bug: Blocks-checkout orders never had
            // the old `_chargeguard_device_fingerprint` key populated at
            // all, so this filter previously always sent a null
            // device_fingerprint for them.
            $fingerprint = ChargeGuard_Dynamic_Firewall::get_order_device_fp($resource_id);
            if ($fingerprint) {
                $payload['device_fingerprint'] = $fingerprint;
            }

            // Server-signed device token (see maybe_issue_device_token() /
            // ChargeGuard_Dynamic_Firewall::get_order_device_token()). This
            // is a NEW top-level field — `_chargeguard_device_token` is a
            // private (underscore-prefixed) meta key, which WooCommerce's
            // webhook payload serializer excludes from `meta_data` by
            // default, so the backend's meta_data fallback lookup in
            // /woocommerce-webhook could never find it. Injecting it
            // explicitly here is the only way to get it into the payload.
            // Omitted entirely (never sent as null/empty) for orders with
            // no token — pre-device-token-feature orders, older plugin
            // versions, or a visitor for whom maybe_issue_device_token()
            // never successfully minted one; the backend already treats a
            // missing deviceToken as 'unsigned', identical to today's
            // behavior on /evaluate and /enrich.
            $device_token = ChargeGuard_Dynamic_Firewall::get_order_device_token($resource_id);
            if ($device_token) {
                $payload['device_token'] = $device_token;
            }
        }
        return $payload;
    }
}

register_deactivation_hook(__FILE__, 'chargeguard_on_deactivation');
/**
 * Runs on plugin deactivation. Deliberately non-destructive: leaves the
 * WooCommerce webhook, API credentials, and all settings intact so
 * reactivating the plugin resumes protection exactly as it was. Only
 * sets a flag so the merchant sees a clear warning on their next admin
 * page load, since the webhook keeps firing while merely deactivated.
 */
function chargeguard_on_deactivation() {
    set_transient('chargeguard_deactivated_notice', 1, WEEK_IN_SECONDS);
}

add_action('admin_notices', 'chargeguard_maybe_show_deactivated_notice');
/**
 * Shows once, on the first admin page load after deactivation, warning
 * that the ChargeGuard webhook (and any PayPal/Stripe integrations) will
 * keep sending order data until the plugin is either reactivated or
 * fully deleted via the Plugins screen.
 */
function chargeguard_maybe_show_deactivated_notice() {
    if (!get_transient('chargeguard_deactivated_notice')) {
        return;
    }
    if (!current_user_can('manage_woocommerce')) {
        return;
    }
    $connected = get_option('chargeguard_api_key');
    if (!$connected) {
        // Store was never connected â€” nothing is still transmitting, no need to warn.
        delete_transient('chargeguard_deactivated_notice');
        return;
    }
    ?>
    <div class="notice notice-warning is-dismissible">
        <p>
            <strong>ChargeGuard has been deactivated</strong> â€” but your store's
            ChargeGuard webhook and settings are still saved and the webhook
            will continue sending order data to ChargeGuard until you either
            reactivate the plugin or remove it completely.
        </p>
        <p>
            To fully disconnect and stop all data sharing: go to
            <strong>Plugins</strong> and click <strong>Delete</strong> under
            ChargeGuard. This will remove the webhook and all stored settings.
            If you configured Stripe or PayPal webhooks directly in those
            dashboards, remove those there as well.
        </p>
    </div>
    <?php
}

add_action('plugins_loaded', 'chargeguard_init');
function chargeguard_init() {
    delete_transient('chargeguard_deactivated_notice');

    if (!class_exists('WooCommerce')) { return; }

    if (is_admin() && !file_exists(__DIR__ . '/vendor/stripe-php/init.php')) {
        add_action('admin_notices', 'chargeguard_missing_stripe_sdk_notice');
    }

    if (is_admin()) { new ChargeGuard_Admin_Settings(); }
    new ChargeGuard_Stripe_Webhook();
new ChargeGuard_PayPal_Webhook();
    new ChargeGuard_Dynamic_Firewall();
    
    new ChargeGuard_Privacy();
    // Device-fingerprint order meta is now written solely by
    // ChargeGuard_Dynamic_Firewall (intercept_checkout_block() /
    // reconcile_pre_order_id()) under the single canonical key
    // `_chargeguard_device_fp` — no separate hook needed here anymore.
    add_filter('woocommerce_webhook_payload', 'chargeguard_add_fingerprint_to_webhook_payload', 10, 4);
}

// Daily refresh of Cloudflare's published IP ranges, entirely off the
// checkout request path — see ChargeGuard_Trusted_Proxy::refresh_cf_ranges().
add_action('chargeguard_refresh_cf_ranges', ['ChargeGuard_Trusted_Proxy', 'refresh_cf_ranges']);
register_activation_hook(__FILE__, function () {
    if (!wp_next_scheduled('chargeguard_refresh_cf_ranges')) {
        wp_schedule_event(time(), 'daily', 'chargeguard_refresh_cf_ranges');
    }
});
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('chargeguard_refresh_cf_ranges');
});

add_action('init', 'chargeguard_init_updater');
function chargeguard_init_updater() {
    if (is_admin()) {
        ChargeGuard_Plugin_Updater::init(__FILE__);
    }
}

function chargeguard_missing_stripe_sdk_notice() {
    ?>
    <div class="notice notice-warning is-dismissible">
        <p>
            <strong>ChargeGuard:</strong>
            The Stripe SDK (<code>vendor/stripe-php</code>) was not found. Stripe webhook enrichment
            (BIN/card intelligence for Stripe orders) is currently disabled. If you installed this
            plugin from source, run <code>composer install</code> in the plugin directory. All other
            ChargeGuard protection features are unaffected.
        </p>
    </div>
    <?php
}

