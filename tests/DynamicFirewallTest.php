<?php
/**
 * Dynamic Firewall Integration Test
 * 
 * يختبر الجدار الناري داخل بيئة ووردبريس حقيقية (قاعدة بيانات مؤقتة).
 */
require_once __DIR__ . '/bootstrap-wp.php';

class DynamicFirewallTest extends WP_UnitTestCase {

    private $firewall;

    public function set_up() {
        parent::set_up();
        delete_option('chargeguard_device_blacklist');
        $this->firewall = new ChargeGuard_Dynamic_Firewall();
    }

    public function testValidSessionTokenPasses() {
        WC()->session->set('chargeguard_checkout_token', 'valid_token_xyz');
        $_POST['chargeguard_session_token'] = 'valid_token_xyz';

        $this->firewall->validate_session_token([]);

        $notices = wc_get_notices('error');
        $this->assertEmpty($notices, 'Expected no error notices for valid token');
    }

    public function testBlacklistedDeviceIsBlocked() {
        $this->firewall->add_device_to_blacklist('fp_blocked_123');
        $_COOKIE['chargeguard_fp'] = 'fp_blocked_123';

        $this->expectException(ChargeGuard_Blocked_Exception::class);
        $this->firewall->check_device_blacklist();
    }
}