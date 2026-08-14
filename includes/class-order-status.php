<?php
/**
 * ChargeGuard - Custom Order Status for security-blocked orders.
 *
 * Registers a dedicated order status ("Blocked by ChargeGuard") that is
 * structurally distinct from WooCommerce's native 'cancelled' status, so
 * ChargeGuard-blocked attempts (bot/fraud traffic) never mix with genuine
 * merchant-initiated cancellations in reporting, the "All" orders view, or
 * cancellation-rate analytics.
 *
 * Slug length note: WordPress stores post_status in a varchar(20) column.
 * 'wc-cg-blocked' is 13 characters -- well under the limit. Do NOT rename
 * this to a longer slug (e.g. 'wc-chargeguard-blocked' = 22 chars) without
 * first confirming the DB column width, or the status will silently
 * truncate/corrupt on save.
 */

defined('ABSPATH') || exit;

class ChargeGuard_Order_Status {

    // Full post_status value as stored in wp_posts.post_status.
    const POST_STATUS = 'wc-cg-blocked';

    // WooCommerce-style status key (no 'wc-' prefix) -- this is what gets
    // passed to $order->update_status() and to the wc_order_statuses filter.
    const STATUS_SLUG = 'cg-blocked';

    public function __construct() {
        add_action('init', [$this, 'register_status']);
        add_filter('wc_order_statuses', [$this, 'register_with_woocommerce']);

        // Defense-in-depth: register_post_status()'s show_in_admin_all_list
        // flag is what WooCommerce's order list table is documented to
        // respect (mirrors WooCommerce's own internal 'wc-checkout-draft'
        // status), but this explicit query filter guarantees the "All" tab
        // never includes cg-blocked orders even if that behavior ever
        // changes in a future WooCommerce version.
        add_filter('request', [$this, 'exclude_from_all_view']);

        // Small visual distinction in the admin order list so a
        // ChargeGuard-blocked row doesn't look identical to a generic
        // unknown/grey status badge.
        add_action('admin_head-edit.php', [$this, 'print_status_badge_css']);
    }

    public function register_status() {
        register_post_status(self::POST_STATUS, [
            'label'                     => _x('Blocked by ChargeGuard', 'Order status', 'chargeguard-woocommerce'),
            'public'                    => false,
            'exclude_from_search'       => true,
            'show_in_admin_all_list'    => false, // excluded from the default "All" view
            'show_in_admin_status_list' => true,  // still gets its own tab/filter link
            'label_count'               => _n_noop(
                'Blocked by ChargeGuard <span class="count">(%s)</span>',
                'Blocked by ChargeGuard <span class="count">(%s)</span>',
                'chargeguard-woocommerce'
            ),
        ]);
    }

    public function register_with_woocommerce($order_statuses) {
        // Inserted right after 'wc-cancelled' purely for a sensible visual
        // grouping in the admin dropdown -- has no functional effect.
        $new_statuses = [];
        foreach ($order_statuses as $key => $label) {
            $new_statuses[$key] = $label;
            if ($key === 'wc-cancelled') {
                $new_statuses['wc-cg-blocked'] = _x('Blocked by ChargeGuard', 'Order status', 'chargeguard-woocommerce');
            }
        }
        // Fallback in case 'wc-cancelled' is ever absent from the array.
        if (!isset($new_statuses['wc-cg-blocked'])) {
            $new_statuses['wc-cg-blocked'] = _x('Blocked by ChargeGuard', 'Order status', 'chargeguard-woocommerce');
        }
        return $new_statuses;
    }

    /**
     * Ensures the default "All" orders view (no explicit ?post_status=
     * in the URL) never includes cg-blocked orders, regardless of
     * whether WooCommerce's list table fully honors
     * show_in_admin_all_list in every version. Only applies to the
     * shop_order list screen, and only when the merchant hasn't
     * explicitly requested a specific status filter (including our own
     * tab, which passes ?post_status=wc-cg-blocked and is left alone).
     */
    public function exclude_from_all_view($vars) {
        global $pagenow, $typenow;

        if (!is_admin() || $pagenow !== 'edit.php' || $typenow !== 'shop_order') {
            return $vars;
        }
        if (!empty($_GET['post_status'])) {
            return $vars; // merchant explicitly chose a tab -- never override
        }

        $all_statuses = array_keys(wc_get_order_statuses());
        $vars['post_status'] = array_values(array_diff($all_statuses, [self::POST_STATUS]));

        return $vars;
    }

    public function print_status_badge_css() {
        $screen = get_current_screen();
        if (!$screen || $screen->post_type !== 'shop_order') {
            return;
        }
        ?>
        <style>
            .order-status.status-cg-blocked {
                background: #f8d7da;
                color: #842029;
            }
        </style>
        <?php
    }
}