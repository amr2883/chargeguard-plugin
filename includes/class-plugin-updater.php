<?php
defined('ABSPATH') || exit;

/**
 * Thin wrapper around Plugin Update Checker (PUC). Only initializes when
 * a connected API key exists — an unlicensed/disconnected install has no
 * key to send to /api/updates/info, so there's nothing to check.
 */
class ChargeGuard_Plugin_Updater {

    private static $update_checker = null;

    public static function init($plugin_file) {
        $puc_bootstrap = __DIR__ . '/../vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php';
        if (!file_exists($puc_bootstrap)) {
            add_action('admin_notices', [__CLASS__, 'missing_puc_notice']);
            return;
        }
        require_once $puc_bootstrap;

        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            return;
        }

        $domain  = wp_parse_url(home_url(), PHP_URL_HOST);
        $channel = apply_filters('chargeguard_update_channel', 'stable');

        $info_url = add_query_arg(
            [
                'key'     => rawurlencode($api_key),
                'domain'  => rawurlencode($domain),
                'channel' => $channel,
            ],
            'https://chargeguard-api.onrender.com/api/updates/info'
        );

        self::$update_checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            $info_url,
            $plugin_file,
            'chargeguard-woocommerce'
        );
    }

    public static function missing_puc_notice() {
        if (!current_user_can('manage_woocommerce')) return;
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><strong>ChargeGuard:</strong> The update checker library (<code>vendor/yahnis-elsts/plugin-update-checker</code>) was not found. Automatic update notifications are disabled. Run <code>composer install</code> in the plugin directory.</p>
        </div>
        <?php
    }

    public static function force_check() {
        if (self::$update_checker) {
            self::$update_checker->checkForUpdates();
        }
    }
}