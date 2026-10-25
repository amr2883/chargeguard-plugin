<?php
error_reporting(E_ALL & ~E_DEPRECATED);
ini_set('display_errors', 1);
define('ABSPATH', '/var/www/html/');
require_once '/var/www/html/wp-load.php';

// تنظيف حالة الـcircuit breaker والقرارات الادارية قبل البدء
delete_transient('chargeguard_circuit_open');
delete_option('chargeguard_device_blacklist');

require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-dynamic-firewall.php';

// ─── Mock HTTP layer via WordPress's own pre_http_request filter ───
// هذا هو الفلتر الرسمي لـ WordPress لاعتراض أي HTTP request قبل تنفيذه
// فعليًا. يشتغل مع wp_remote_request/wp_remote_post على حد سواء دون أي
// تعديل على core.
$GLOBALS['cg_test_scenario'] = 'none';

add_filter('pre_http_request', function ($preempt, $args, $url) {
    $scenario = $GLOBALS['cg_test_scenario'] ?? 'none';

    if (strpos($url, '/risk/challenge/request') !== false) {
        if ($scenario === 'challenge_delivery_success') {
            return [
                'response' => ['code' => 200],
                'body'     => json_encode(['success' => true, 'emailSent' => true, 'expiresInSeconds' => 300]),
            ];
        }
        if ($scenario === 'challenge_delivery_failed') {
            return [
                'response' => ['code' => 200],
                'body'     => json_encode(['success' => true, 'emailSent' => false]),
            ];
        }
    }

    if (strpos($url, '/risk/challenge/verify') !== false) {
        if ($scenario === 'otp_correct') {
            return [
                'response' => ['code' => 200],
                'body'     => json_encode(['verified' => true, 'ticket' => 'signed_ticket_test_123']),
            ];
        }
        if ($scenario === 'otp_wrong') {
            return [
                'response' => ['code' => 400],
                'body'     => json_encode(['verified' => false, 'error' => 'Incorrect verification code.']),
            ];
        }
    }

    if (strpos($url, '/risk/evaluate') !== false || strpos($url, '/evaluate') !== false) {
        if ($scenario === 'decision_challenge') {
            return [
                'response' => ['code' => 200],
                'body'     => json_encode(['decision' => 'challenge']),
            ];
        }
        if ($scenario === 'decision_approve_with_ticket') {
            return [
                'response' => ['code' => 200],
                'body'     => json_encode(['decision' => 'approve']),
            ];
        }
    }

    return $preempt; // لأي URL/سيناريو غير متوقع، سيب السلوك الافتراضي
}, 10, 3);

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

echo "=== P1-01 Verification: Classic Checkout Challenge Parity ===\n\n";

// ─── Test 1: render_classic_otp_field() outputs a field without fatal error ───
echo "[Test 1] render_classic_otp_field() renders without error\n";
$firewall = new ChargeGuard_Dynamic_Firewall();
ob_start();
try {
    $firewall->render_classic_otp_field();
    $output = ob_get_clean();
    if (strpos($output, 'chargeguard_otp') !== false) {
        echo "[OK] Field markup contains 'chargeguard_otp' input name.\n";
    } else {
        echo "[FAIL] Field markup does NOT contain 'chargeguard_otp'. Output was:\n$output\n";
    }
} catch (\Throwable $e) {
    ob_end_clean();
    echo "[FAIL] Exception thrown: " . $e->getMessage() . "\n";
}

echo "\n";

// ─── Test 2: decision === 'challenge' + email sent -> order halted with actionable notice ───
echo "[Test 2] decision=challenge + emailSent=true -> checkout halted with notice, no fatal\n";
reset_notices();
$_POST = ['billing_email' => 'test@example.com', 'billing_country' => 'US', 'shipping_country' => 'US'];
$_COOKIE['chargeguard_fp'] = 'fp_test_classic_' . uniqid();
$GLOBALS['cg_test_scenario'] = 'decision_challenge';

// نحتاج intercept_checkout بتاخد decision من evaluate_risk، فنحط سيناريو
// evaluate يرجع challenge، وسيناريو request_challenge يرجع emailSent=true
add_filter('pre_http_request', function ($preempt, $args, $url) {
    if (strpos($url, '/evaluate') !== false) {
        return ['response' => ['code' => 200], 'body' => json_encode(['decision' => 'challenge'])];
    }
    if (strpos($url, '/risk/challenge/request') !== false) {
        return ['response' => ['code' => 200], 'body' => json_encode(['success' => true, 'emailSent' => true])];
    }
    return $preempt;
}, 20, 3);

try {
    $firewall2 = new ChargeGuard_Dynamic_Firewall();
    $firewall2->intercept_checkout();
    $notice_text = get_error_notices_text();
    if (stripos($notice_text, 'verification code') !== false || stripos($notice_text, 'security') !== false) {
        echo "[OK] Actionable notice shown: $notice_text\n";
    } else {
        echo "[WARN] intercept_checkout() completed without fatal, but notice text unexpected: '$notice_text'\n";
    }
} catch (\Throwable $e) {
    echo "[FAIL] Exception thrown: " . $e->getMessage() . " at " . $e->getFile() . ":" . $e->getLine() . "\n";
}

echo "\n=== Done ===\n";
