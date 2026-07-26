<?php
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/mocks.php';

require_once __DIR__ . '/../includes/class-api-client.php';

class ApiClientTest extends TestCase
{
    public function testGenerateHmacReturnsValidBase64()
    {
        // set up secret via our mock get_option
        $GLOBALS['test_value_chargeguard_webhook_secret'] = '';

        $client = $this->getMockBuilder(ChargeGuard_API_Client::class)
                       ->disableOriginalConstructor()
                       ->onlyMethods([])
                       ->getMock();

        $ref = new ReflectionMethod(ChargeGuard_API_Client::class, 'generate_hmac');
        $ref->setAccessible(true);
        $sig = $ref->invoke($client, 'test');

        $expected = base64_encode(hash_hmac('sha256', 'test', '', true));
        $this->assertEquals($expected, $sig);
    }

       public function testSendEnrichReturnsSuccessfulResponse()
    {
        $GLOBALS['test_value_chargeguard_api_key'] = 'key123';
        $GLOBALS['test_value_chargeguard_merchant_id'] = 'merchant123';
        $GLOBALS['test_value_chargeguard_webhook_secret'] = 'wsecret';
        $GLOBALS['mock_wp_remote_success'] = true;
        $GLOBALS['mock_wp_remote_body'] = '{"success":true,"enriched":true}';

        $client = new ChargeGuard_API_Client();

        $data = ['orderId' => '123', 'bin' => '424242'];
        $result = $client->send_enrich($data);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('success', $result);
        $this->assertTrue($result['success']);
    }
}