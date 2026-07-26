<?php
// Shared mock functions for all tests — required once

if (!function_exists('get_option')) {
    function get_option($key) {
        return 'test_value_' . $key;
    }
}

if (!function_exists('wp_remote_post')) {
    function wp_remote_post($url, $args) {
        // دعم الفشل الدائم
        if (!empty($GLOBALS['mock_wp_remote_fail_always'])) {
            return new WP_Error('http_failure', 'Simulated failure');
        }
        // دعم callback مخصص للتحكم الكامل
        if (isset($GLOBALS['mock_wp_remote_response_callback'])) {
            return call_user_func($GLOBALS['mock_wp_remote_response_callback']);
        }
        // Capture enrich data for testing
        if (strpos($url, '/enrich') !== false && isset($args['body'])) {
            $GLOBALS['captured_enrich_data'] = json_decode($args['body'], true);
        }
        $success = isset($GLOBALS['mock_wp_remote_success']) ? $GLOBALS['mock_wp_remote_success'] : true;
        $body = isset($GLOBALS['mock_wp_remote_body']) ? $GLOBALS['mock_wp_remote_body'] : '{"success":true}';
        return [
            'response' => ['code' => $success ? 200 : 500],
            'body' => $body,
        ];
    }
}

if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body($response) {
        return $response['body'];
    }
}

if (!function_exists('wp_remote_retrieve_response_code')) {
    function wp_remote_retrieve_response_code($response) {
        return $response['response']['code'];
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($response) {
        return $response instanceof WP_Error;
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error {
        public function __construct($code, $msg) {}
    }
}

if (!function_exists('register_rest_route')) {
    function register_rest_route($namespace, $route, $args) {
        $GLOBALS['registered_routes'][$namespace . $route] = $args;
    }
}

if (!function_exists('wc_get_orders')) {
    function wc_get_orders($args) {
        return isset($GLOBALS['mock_wc_get_orders_returns']) ? $GLOBALS['mock_wc_get_orders_returns'] : [];
    }
}

if (!function_exists('set_transient')) {
    function set_transient($name, $value, $expiration) { return true; }
}

if (!function_exists('__')) {
    function __($text, $domain = '') { return $text; }
}

if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}

if (!class_exists('WP_REST_Response')) {
    class WP_REST_Response {
        public $status;
        public function __construct($data = null, $status = 200) {
            $this->status = $status;
        }
    }
}

if (!function_exists('add_action')) {
    function add_action($hook, $callback) {
        if ($hook === 'rest_api_init') {
            $callback();
        }
    }
}