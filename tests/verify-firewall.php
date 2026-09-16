<?php
error_reporting(0);
ini_set('display_errors', 0);
define('ABSPATH', '/var/www/html/');
require_once '/var/www/html/wp-load.php';
require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-dynamic-firewall.php';

$firewall = new ChargeGuard_Dynamic_Firewall();
delete_option('chargeguard_device_blacklist');
$firewall->add_device_to_blacklist('fp_verify_test');

$_COOKIE['chargeguard_fp'] = 'fp_verify_test';

try {
    $firewall->check_device_blacklist();
    echo '[FAIL] Exception not thrown\n';
} catch (ChargeGuard_Blocked_Exception $e) {
    echo '[OK] Firewall working: ' . $e->getMessage() . '\n';
}