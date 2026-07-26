<?php
/**
 * ChargeGuard - Manual Firewall Test
 *
 * يختبر الجدار الناري في بيئة ووردبريس حقيقية.
 * يثبت أن الأجهزة المحظورة تُمنع من الوصول.
 *
 * @package ChargeGuard_WooCommerce
 */

// كتم التحذيرات لتكون المخرجات نظيفة
error_reporting(0);
ini_set('display_errors', 0);

// تحميل نواة ووردبريس
define('ABSPATH', '/var/www/html/');
require_once '/var/www/html/wp-load.php';

// تحميل ملفات الإضافة
require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-dynamic-firewall.php';

// بدء الاختبار
echo "=== ChargeGuard Firewall Manual Test ===\n\n";

// 1. إعداد البيئة
delete_option('chargeguard_device_blacklist');
$firewall = new ChargeGuard_Dynamic_Firewall();

// 2. إضافة بصمة إلى القائمة السوداء
$fingerprint = 'fp_test_success';
$firewall->add_device_to_blacklist($fingerprint);
echo "[SETUP] Fingerprint '$fingerprint' added to blacklist\n";

// 3. محاكاة كوكي المتصفح
$_COOKIE['chargeguard_fp'] = $fingerprint;

// 4. محاولة الوصول (يجب أن يفشل)
echo "[TEST] Attempting checkout access...\n";
try {
    $firewall->check_device_blacklist();
    // إذا وصلنا إلى هنا، فالاختبار فشل
    echo "[FAIL] Blacklisted device was NOT blocked!\n";
} catch (ChargeGuard_Blocked_Exception $e) {
    // هذا هو السلوك المتوقع
    echo "[PASS] Blacklisted device blocked.\n";
    echo "       Message: " . $e->getMessage() . "\n";
} catch (\Throwable $e) {
    // أي خطأ آخر غير متوقع
    echo "[ERROR] Unexpected exception: " . get_class($e) . "\n";
    echo "        " . $e->getMessage() . "\n";
}

echo "\n--- Test Complete ---\n";