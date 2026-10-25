<?php
error_reporting(E_ALL & ~E_DEPRECATED);
ini_set('display_errors', 1);
define('ABSPATH', '/var/www/html/');
require_once '/var/www/html/wp-load.php';

delete_transient('chargeguard_circuit_open');
delete_option('chargeguard_device_blacklist');

require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-dynamic-firewall.php';

function reset_notices() {
    if (function_exists('wc_clear_notices')) {
        wc_clear_notices();
    }
}

function get_error_notices_text() {
    $notices = function_exists('wc_get_notices') ? wc_get_notices('error') : [];
    return implode(' | ', array_map(function ($n) {
        return is_array($n) ? ($n['notice'] ?? '') : $n;
    }, $notices));
}

echo "=== P1-01 Verification Part 2: OTP verify + rate-limit paths ===\n\n";

// ─── Test 3: correct OTP -> ticket minted, no error notice, checkout proceeds ───
echo "[Test 3] OTP correct -> ticket minted, no error notice\n";
reset_notices();
add_filter('pre_http_request', function ($preempt, $args, $url) {
    if (strpos($url, '/risk/challenge/verify') !== false) {
        return ['response' => ['code' => 200], 'body' => json_encode(['verified' => true, 'ticket' => 'ticket_abc_123'])];
    }
    if (strpos($url, '/evaluate') !== false) {
        return ['response' => ['code' => 200], 'body' => json_encode(['decision' => 'approve'])];
    }
    return $preempt;
}, 30, 3);

$_POST = [
    'billing_email'     => 'test3@example.com',
    'billing_country'   => 'US',
    'shipping_country'  => 'US',
    'chargeguard_otp'   => '123456',
];
$_COOKIE['chargeguard_fp'] = 'fp_test3_' . uniqid();
unset($_COOKIE['chargeguard_ct']);

try {
    $fw3 = new ChargeGuard_Dynamic_Firewall();
    $fw3->intercept_checkout();
    $notice_text = get_error_notices_text();
    if ($notice_text === '') {
        echo "[OK] No error notice - checkout proceeded normally after ticket mint.\n";
    } else {
        echo "[FAIL] Unexpected notice after correct OTP: $notice_text\n";
    }
} catch (\Throwable $e) {
    echo "[FAIL] Exception: " . $e->getMessage() . " at " . $e->getFile() . ":" . $e->getLine() . "\n";
}

echo "\n";

// ─── Test 4: wrong OTP -> actionable error notice, halted ───
echo "[Test 4] OTP wrong -> actionable error notice\n";
reset_notices();
add_filter('pre_http_request', function ($preempt, $args, $url) {
    if (strpos($url, '/risk/challenge/verify') !== false) {
        return ['response' => ['code' => 400], 'body' => json_encode(['verified' => false, 'error' => 'Incorrect verification code.'])];
    }
    return $preempt;
}, 40, 3);

$_POST = [
    'billing_email'     => 'test4@example.com',
    'billing_country'   => 'US',
    'shipping_country'  => 'US',
    'chargeguard_otp'   => '000000',
];
$_COOKIE['chargeguard_fp'] = 'fp_test4_' . uniqid();
unset($_COOKIE['chargeguard_ct']);

try {
    $fw4 = new ChargeGuard_Dynamic_Firewall();
    $fw4->intercept_checkout();
    $notice_text = get_error_notices_text();
    if (stripos($notice_text, 'incorrect') !== false || stripos($notice_text, 'expired') !== false) {
        echo "[OK] Actionable error notice shown: $notice_text\n";
    } else {
        echo "[WARN] Notice text unexpected: '$notice_text'\n";
    }
} catch (\Throwable $e) {
    echo "[FAIL] Exception: " . $e->getMessage() . " at " . $e->getFile() . ":" . $e->getLine() . "\n";
}

echo "\n";

// ─── Test 5: emailSent=false but under rate limit -> fail-open, no fatal, no notice about it ───
echo "[Test 5] challenge requested but delivery unconfirmed, under rate limit -> proceeds without notice\n";
reset_notices();
add_filter('pre_http_request', function ($preempt, $args, $url) {
    if (strpos($url, '/evaluate') !== false) {
        return ['response' => ['code' => 200], 'body' => json_encode(['decision' => 'challenge'])];
    }
    if (strpos($url, '/risk/challenge/request') !== false) {
        return ['response' => ['code' => 200], 'body' => json_encode(['success' => true, 'emailSent' => false])];
    }
    return $preempt;
}, 50, 3);

$_POST = [
    'billing_email'     => 'test5@example.com',
    'billing_country'   => 'US',
    'shipping_country'  => 'US',
];
$_COOKIE['chargeguard_fp'] = 'fp_test5_' . uniqid();
unset($_COOKIE['chargeguard_otp'], $_POST['chargeguard_otp'], $_COOKIE['chargeguard_ct']);

try {
    $fw5 = new ChargeGuard_Dynamic_Firewall();
    $fw5->intercept_checkout();
    $notice_text = get_error_notices_text();
    echo "[INFO] No exception thrown. Notice text (expected likely empty under fail-open): '$notice_text'\n";
} catch (\Throwable $e) {
    echo "[FAIL] Exception: " . $e->getMessage() . " at " . $e->getFile() . ":" . $e->getLine() . "\n";
}

echo "\n=== Done ===\n";
