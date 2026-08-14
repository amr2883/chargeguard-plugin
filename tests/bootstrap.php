<?php
/**
 * PHPUnit Bootstrap – يهيئ بيئة WordPress للاختبارات
 */

// منع تحذير HTTP_HOST في CLI
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['REQUEST_URI'] = '/';

// تحميل نواة ووردبريس
require_once '/var/www/html/wp-load.php';

// تفعيل WooCommerce إذا لم يكن مفعلاً
if (!class_exists('WooCommerce')) {
    require_once '/var/www/html/wp-content/plugins/woocommerce/woocommerce.php';
}

// تضمين ملفات الإضافة الخاصة بنا
require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-dynamic-firewall.php';