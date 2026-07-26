<?php
/**
 * ChargeGuard - Remote Config Viewer (read-only)
 *
 * Exposes a small, explicitly allow-listed subset of plugin settings over
 * a REST route so ChargeGuard support can diagnose proxy/firewall/auto-block
 * misconfigurations without asking the merchant to screen-share or read
 * settings aloud. Read-only, allow-listed, and gated by a dedicated shared
 * secret - never the merchant's chargeguard_api_key.
 *
 * @package ChargeGuard_WooCommerce
 */

defined('ABSPATH') || exit;

class ChargeGuard_Remote_Config {

    const ADMIN_CONFIG_KEY_OPTION = 'chargeguard_admin_config_key';
    const LAST_USED_OPTION        = 'chargeguard_admin_config_key_last_used';

    const ALLOWED_OPTIONS = [
        'chargeguard_enable_firewall',
        'chargeguard_firewall_block_duration',
        'chargeguard_trust_proxy_headers',
        'chargeguard_proxy_trust_mode',
        'chargeguard_trusted_proxy_cidrs',
        'chargeguard_auto_block',
        'chargeguard_auto_refund',
        'chargeguard_api_down_behavior',
        'chargeguard_api_down_rate_limit',
        'chargeguard_block_min_amount',
    ];

    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
        add_action('admin_init', [$this, 'maybe_generate_admin_config_key']);
        add_action('admin_notices', [$this, 'maybe_show_config_key_notice']);
        add_action('wp_ajax_chargeguard_remoteconfig_reveal',     [$this, 'ajax_reveal_key']);
        add_action('wp_ajax_chargeguard_remoteconfig_regenerate', [$this, 'ajax_regenerate_key']);
        add_action('wp_ajax_chargeguard_remoteconfig_revoke',     [$this, 'ajax_revoke_key']);
    }

    public function register_routes() {
        register_rest_route('chargeguard/v1', '/admin/settings', [
            'methods'             => 'GET',
            'callback'            => [$this, 'handle_get_settings'],
            'permission_callback' => [$this, 'check_admin_config_key'],
        ]);
    }

    /**
     * Auto-generates a random per-install secret the first time this file
     * loads on an admin request. Stored encrypted via the shared secret
     * helpers defined in class-admin-settings.php (loaded earlier in the
     * plugin's require_once chain), exactly like Stripe/PayPal secrets.
     */
    public function maybe_generate_admin_config_key() {
        if (!chargeguard_get_secret_option(self::ADMIN_CONFIG_KEY_OPTION)) {
            chargeguard_update_secret_option(self::ADMIN_CONFIG_KEY_OPTION, wp_generate_password(40, false, false));
        }
    }

    /**
     * Only ever shown on the ChargeGuard settings screen itself - never
     * globally across wp-admin - and the key is never printed into the
     * page HTML directly. It's masked by default; "Show" fetches the raw
     * value via a capability + nonce gated AJAX call on demand.
     */
    public function maybe_show_config_key_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        if (empty($_GET['page']) || $_GET['page'] !== 'chargeguard-settings') {
            return;
        }

        $key = chargeguard_get_secret_option(self::ADMIN_CONFIG_KEY_OPTION);
        if (!$key) {
            return;
        }

        $masked = substr($key, 0, 4) . str_repeat('*', max(0, strlen($key) - 8)) . substr($key, -4);

        $last_used = get_option(self::LAST_USED_OPTION);
        if (is_array($last_used) && !empty($last_used['time'])) {
            $last_used_text = sprintf(
                'Last used: %s from IP %s',
                esc_html(gmdate('Y-m-d H:i:s \U\T\C', (int) $last_used['time'])),
                esc_html($last_used['ip'] ?? 'unknown')
            );
        } else {
            $last_used_text = 'Never used yet.';
        }

        $reveal_nonce     = wp_create_nonce('chargeguard_remoteconfig_reveal');
        $regenerate_nonce = wp_create_nonce('chargeguard_remoteconfig_regenerate');
        $revoke_nonce     = wp_create_nonce('chargeguard_remoteconfig_revoke');
        ?>
        <div class="notice notice-info" id="cg-remoteconfig-notice">
            <p>
                <strong>ChargeGuard Remote Config Key</strong>
                &mdash; share this with ChargeGuard support only if they ask for it, to enable
                the read-only "View Config" diagnostic tool. It grants read-only access to a
                small set of non-secret settings only.
            </p>
            <p>
                <code id="cg-rc-key-display"><?php echo esc_html($masked); ?></code>
                <button type="button" class="button button-small" id="cg-rc-show-btn">Show</button>
                <button type="button" class="button button-small" id="cg-rc-copy-btn" style="display:none;">Copy</button>
                &nbsp;&nbsp;
                <button type="button" class="button button-small" id="cg-rc-regen-btn">Regenerate</button>
                <button type="button" class="button button-small" id="cg-rc-revoke-btn" style="color:#b32d2e;">Revoke Access</button>
            </p>
            <p style="font-size:12px;color:#666;" id="cg-rc-lastused"><?php echo esc_html($last_used_text); ?></p>
            <p style="font-size:12px;color:#b32d2e;display:none;" id="cg-rc-message"></p>
        </div>
        <script>
        (function () {
            var fullKey = null;
            var displayEl = document.getElementById('cg-rc-key-display');
            var showBtn   = document.getElementById('cg-rc-show-btn');
            var copyBtn   = document.getElementById('cg-rc-copy-btn');
            var regenBtn  = document.getElementById('cg-rc-regen-btn');
            var revokeBtn = document.getElementById('cg-rc-revoke-btn');
            var msgEl     = document.getElementById('cg-rc-message');

            function showMessage(text, isError) {
                msgEl.textContent = text;
                msgEl.style.color = isError ? '#b32d2e' : '#2271b1';
                msgEl.style.display = 'block';
            }

            function post(action, nonce, extra) {
                var body = new URLSearchParams(Object.assign({ action: action, nonce: nonce }, extra || {}));
                return fetch(ajaxurl, { method: 'POST', credentials: 'same-origin', body: body })
                    .then(function (r) { return r.json(); });
            }

            showBtn.addEventListener('click', function () {
                if (fullKey) {
                    displayEl.textContent = fullKey;
                    showBtn.style.display = 'none';
                    copyBtn.style.display = 'inline-block';
                    return;
                }
                post('chargeguard_remoteconfig_reveal', '<?php echo esc_js($reveal_nonce); ?>').then(function (res) {
                    if (res.success) {
                        fullKey = res.data.key;
                        displayEl.textContent = fullKey;
                        showBtn.style.display = 'none';
                        copyBtn.style.display = 'inline-block';
                    } else {
                        showMessage(res.data && res.data.message ? res.data.message : 'Failed to reveal key.', true);
                    }
                });
            });

            copyBtn.addEventListener('click', function () {
                if (fullKey) {
                    navigator.clipboard.writeText(fullKey);
                    showMessage('Copied to clipboard.', false);
                }
            });

            regenBtn.addEventListener('click', function () {
                if (!confirm('This will invalidate the current key immediately. Any previously shared key will stop working. Continue?')) {
                    return;
                }
                post('chargeguard_remoteconfig_regenerate', '<?php echo esc_js($regenerate_nonce); ?>').then(function (res) {
                    if (res.success) {
                        fullKey = res.data.key;
                        displayEl.textContent = fullKey;
                        showBtn.style.display = 'none';
                        copyBtn.style.display = 'inline-block';
                        showMessage('New key generated. Share the new value with support.', false);
                    } else {
                        showMessage(res.data && res.data.message ? res.data.message : 'Failed to regenerate key.', true);
                    }
                });
            });

            revokeBtn.addEventListener('click', function () {
                if (!confirm('This will permanently disable the Remote Config diagnostic endpoint until a new key is generated. Continue?')) {
                    return;
                }
                post('chargeguard_remoteconfig_revoke', '<?php echo esc_js($revoke_nonce); ?>').then(function (res) {
                    if (res.success) {
                        document.getElementById('cg-remoteconfig-notice').style.display = 'none';
                        showMessage('Access revoked.', false);
                    } else {
                        showMessage(res.data && res.data.message ? res.data.message : 'Failed to revoke key.', true);
                    }
                });
            });
        })();
        </script>
        <?php
    }

    private function get_client_ip_for_logging() {
        if (class_exists('ChargeGuard_Dynamic_Firewall') && method_exists('ChargeGuard_Dynamic_Firewall', 'get_client_ip')) {
            return ChargeGuard_Dynamic_Firewall::get_client_ip();
        }
        return !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
    }

    public function ajax_reveal_key() {
        check_ajax_referer('chargeguard_remoteconfig_reveal', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $key = chargeguard_get_secret_option(self::ADMIN_CONFIG_KEY_OPTION);
        if (!$key) {
            wp_send_json_error(['message' => 'No key configured.']);
        }
        wp_send_json_success(['key' => $key]);
    }

    public function ajax_regenerate_key() {
        check_ajax_referer('chargeguard_remoteconfig_regenerate', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $new_key = wp_generate_password(40, false, false);
        chargeguard_update_secret_option(self::ADMIN_CONFIG_KEY_OPTION, $new_key);
        delete_option(self::LAST_USED_OPTION);
        wp_send_json_success(['key' => $new_key]);
    }

    public function ajax_revoke_key() {
        check_ajax_referer('chargeguard_remoteconfig_revoke', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        delete_option(self::ADMIN_CONFIG_KEY_OPTION);
        delete_option(self::LAST_USED_OPTION);
        wp_send_json_success();
    }

    /**
     * Constant-time comparison against the Authorization header. Records
     * last-used time/IP on every successful call so the merchant can see
     * in the settings page whether this channel has actually been used.
     */
    public function check_admin_config_key(\WP_REST_Request $request) {
        $expected = chargeguard_get_secret_option(self::ADMIN_CONFIG_KEY_OPTION);
        if (!$expected) {
            return new \WP_Error('chargeguard_not_configured', 'Remote config key not set up.', ['status' => 503]);
        }

        $auth = $request->get_header('authorization');
        $provided = '';
        if ($auth && stripos($auth, 'Bearer ') === 0) {
            $provided = trim(substr($auth, 7));
        }

        $valid = strlen($provided) === strlen($expected) && hash_equals($expected, $provided);
        if (!$valid) {
            return new \WP_Error('chargeguard_forbidden', 'Invalid or missing remote config key.', ['status' => 403]);
        }

        update_option(self::LAST_USED_OPTION, [
            'time' => time(),
            'ip'   => $this->get_client_ip_for_logging(),
        ]);

        return true;
    }

    public function handle_get_settings(\WP_REST_Request $request) {
        $defaults = [
            'chargeguard_enable_firewall'          => 1,
            'chargeguard_firewall_block_duration'  => 24,
            'chargeguard_trust_proxy_headers'      => 0,
            'chargeguard_proxy_trust_mode'         => null,
            'chargeguard_trusted_proxy_cidrs'      => '',
            'chargeguard_auto_block'               => 1,
            'chargeguard_auto_refund'              => 0,
            'chargeguard_api_down_behavior'        => 'local_checks',
            'chargeguard_api_down_rate_limit'      => 3,
            'chargeguard_block_min_amount'         => 0,
        ];

        $settings = [];
        foreach (self::ALLOWED_OPTIONS as $option_name) {
            $default = array_key_exists($option_name, $defaults) ? $defaults[$option_name] : null;
            $settings[$option_name] = get_option($option_name, $default);
        }

        return new \WP_REST_Response([
            'success'          => true,
            'settings'         => $settings,
            'pluginVersion'    => defined('CHARGEGUARD_VERSION') ? CHARGEGUARD_VERSION : null,
            'fetchedAtServer'  => gmdate('c'),
        ], 200);
    }
}
