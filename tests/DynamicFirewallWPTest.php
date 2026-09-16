<?php
require_once __DIR__ . '/bootstrap-wp.php';

class DynamicFirewallWPTest extends WP_UnitTestCase {

    private $firewall;

    public function set_up() {
        parent::set_up();
        delete_option('chargeguard_device_blacklist');
        $this->firewall = new ChargeGuard_Dynamic_Firewall();
    }

    public function test_blacklisted_device_is_blocked() {
        $this->firewall->add_device_to_blacklist('fp_test_999');
        $_COOKIE['chargeguard_fp'] = 'fp_test_999';
        $this->firewall->check_device_blacklist();
    }
}