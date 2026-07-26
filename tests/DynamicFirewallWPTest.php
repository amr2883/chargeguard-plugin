<?php
require_once __DIR__ . '/bootstrap-wp.php';

class DynamicFirewallWPTest extends WP_UnitTestCase {

    private \;

    public function set_up() {
        parent::set_up();
        delete_option('chargeguard_device_blacklist');
        \->firewall = new ChargeGuard_Dynamic_Firewall();
    }

    public function test_blacklisted_device_is_blocked() {
        \->firewall->add_device_to_blacklist('fp_test_999');
        \['chargeguard_fp'] = 'fp_test_999';
        \->expectException(ChargeGuard_Blocked_Exception::class);
        \->firewall->check_device_blacklist();
    }
}
