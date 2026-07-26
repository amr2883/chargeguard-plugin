<?php
/**
 * ChargeGuard for WooCommerce — Uninstall
 *
 * Fires only when the plugin is deleted via wp-admin (Plugins screen),
 * never on simple deactivation. Removes every trace of ChargeGuard:
 * the WooCommerce webhook, all plugin options, all transients
 * (including dynamically-keyed ones), and order meta.
 *
 * @package ChargeGuard_WooCommerce
 */

// Guard: this file must only ever run through WordPress's own uninstall
// flow, never be requested directly.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

/**
 * 1. Delete the WooCommerce webhook we created, if WooCommerce (and the
 *    WC_Webhook class) is still available. If WooCommerce has already been
 *    removed first, the webhook row will already be gone along with
 *    WooCommerce's own tables, so there's nothing to do.
 */
$chargeguard_webhook_id = get_option( 'chargeguard_webhook_id' );
if ( $chargeguard_webhook_id && class_exists( 'WC_Webhook' ) ) {
    $webhook = new WC_Webhook( (int) $chargeguard_webhook_id );
    if ( $webhook->get_id() ) {
        $webhook->delete( true );
    }
}

/**
 * 2. Delete all known fixed-name options.
 */
$chargeguard_options = [
    'chargeguard_api_key',
    'chargeguard_api_signing_secret',
    'chargeguard_merchant_id',
    'chargeguard_webhook_secret',
    'chargeguard_connected_email',
    'chargeguard_webhook_id',
    'chargeguard_enable_firewall',
    'chargeguard_firewall_block_duration',
    'chargeguard_trust_proxy_headers',
    'chargeguard_badge_enabled',
    'chargeguard_badge_location',
    'chargeguard_badge_color',
    'chargeguard_paypal_client_id',
    'chargeguard_paypal_client_secret',
    'chargeguard_paypal_webhook_id',
    'chargeguard_paypal_mode',
    'chargeguard_paypal_enabled',
    'chargeguard_circuit_status',
    'chargeguard_signing_self_test',
    'chargeguard_secret_decrypt_failures',
    'chargeguard_device_blacklist',
    'chargeguard_stripe_webhook_secret',
    'chargeguard_stripe_secret_key',
    'chargeguard_stripe_enabled',
    'chargeguard_auto_block',
    'chargeguard_block_min_amount',
    'chargeguard_deactivated_notice',
];

foreach ( $chargeguard_options as $option_name ) {
    delete_option( $option_name );
}

/**
 * 3. Delete fixed-name transients (removes both the value and its
 *    timeout row via delete_transient()).
 */
$chargeguard_fixed_transients = [
    'chargeguard_circuit_failures',
    'chargeguard_circuit_open',
    'chargeguard_pending_connect',
];

foreach ( $chargeguard_fixed_transients as $transient_name ) {
    delete_transient( $transient_name );
}

/**
 * 4. Sweep dynamically-keyed transients by LIKE pattern, since we don't
 *    have the full list of IDs that were used to build these keys
 *    (client IDs, PayPal transmission IDs, Stripe event IDs, payment
 *    intent IDs). Handles both the transient value row and its paired
 *    timeout row, for both single-site and network ("site") transients.
 */
$chargeguard_transient_prefixes = [
    'cg_paypal_access_token_',
    'cg_pp_processed_',
    'cg_stripe_processed_',
    'chargeguard_pending_enrich_',
    'chargeguard_secret_decrypt_logged_',
];

foreach ( $chargeguard_transient_prefixes as $prefix ) {
    $like = $wpdb->esc_like( '_transient_' . $prefix ) . '%';
    $like_timeout = $wpdb->esc_like( '_transient_timeout_' . $prefix ) . '%';
    $like_site = $wpdb->esc_like( '_site_transient_' . $prefix ) . '%';
    $like_site_timeout = $wpdb->esc_like( '_site_transient_timeout_' . $prefix ) . '%';

    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
            $like,
            $like_timeout,
            $like_site,
            $like_site_timeout
        )
    );
}

// If an external object cache is in use, transients may live there
// instead of wp_options — clear it too so nothing lingers in cache.
wp_cache_flush();

/**
 * 5. Delete order meta added by ChargeGuard. Scoped to postmeta rows on
 *    'shop_order' posts (and HPOS order tables, if WooCommerce's
 *    High-Performance Order Storage is enabled) to avoid touching
 *    unrelated meta.
 */
$chargeguard_order_meta_keys = [
    '_chargeguard_device_fingerprint',
    '_chargeguard_payment_intent_id',
    '_chargeguard_pre_order_id',
];

foreach ( $chargeguard_order_meta_keys as $meta_key ) {
    // Legacy postmeta storage.
    $wpdb->delete( $wpdb->postmeta, [ 'meta_key' => $meta_key ] ); // phpcs:ignore WordPress.DB.SlowDBQuery

    // HPOS ("High-Performance Order Storage") custom orders table, if active.
    $hpos_meta_table = $wpdb->prefix . 'wc_orders_meta';
    if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $hpos_meta_table ) ) === $hpos_meta_table ) {
        $wpdb->delete( $hpos_meta_table, [ 'meta_key' => $meta_key ] ); // phpcs:ignore WordPress.DB.SlowDBQuery
    }
}