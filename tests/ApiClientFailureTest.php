<?php
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/mocks.php';
require_once __DIR__ . '/../includes/class-api-client.php';

class ApiClientFailureTest extends TestCase
{
    public function testSendEnrichRetriesOnFailure()
    {
        // نجعلها تفشل في المرة الأولى، ثم تنجح في الثانية
        $callCount = 0;
        $GLOBALS['mock_wp_remote_response_callback'] = function() use (&$callCount) {
            $callCount++;
            if ($callCount === 1) {
                return new WP_Error('http_failure', 'Timeout');
            }
            return [
                'response' => ['code' => 200],
                'body' => '{"success":true}',
            ];
        };

        $GLOBALS['test_value_chargeguard_api_key'] = 'key';
        $GLOBALS['test_value_chargeguard_merchant_id'] = 'merchant';
        $GLOBALS['test_value_chargeguard_webhook_secret'] = 'secret';

        $client = new ChargeGuard_API_Client();
        $data = ['orderId' => '123', 'bin' => '424242'];
        $result = $client->send_enrich($data);

        // بعد إعادة المحاولة الناجحة، يجب أن نحصل على مصفوفة
        $this->assertIsArray($result);
        $this->assertTrue($result['success']);
    }
}