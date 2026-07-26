<?php
// تحميل البنية التحتية الرسمية للاختبارات
require_once '/var/www/html/wp-tests/bootstrap.php';

// تحميل WooCommerce إذا لم يكن محملاً
if (!class_exists('WooCommerce')) {
    require_once '/var/www/html/wp-content/plugins/woocommerce/woocommerce.php';
}

// تحميل ملفات الإضافة الخاصة بنا
require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-dynamic-firewall.php';
