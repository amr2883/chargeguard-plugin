<?php
error_reporting(0);
ini_set('display_errors', 0);
define('ABSPATH', '/var/www/html/');
require_once '/var/www/html/wp-load.php';
require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-dynamic-firewall.php';

\ = new ChargeGuard_Dynamic_Firewall();
delete_option('chargeguard_device_blacklist');
\->add_device_to_blacklist('fp_verify_test');

\['chargeguard_fp'] = 'fp_verify_test';

try {
    \->check_device_blacklist();
    echo '[FAIL] Exception not thrown\n';
} catch (ChargeGuard_Blocked_Exception \) {
    echo '[OK] Firewall working: ' . \->getMessage() . '\n';
}
echo 'Done\n';
