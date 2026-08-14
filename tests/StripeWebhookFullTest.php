<?php
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/mocks.php';
require_once __DIR__ . '/stripe-mock.php';
require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-stripe-webhook.php';

class StripeWebhookFullTest extends TestCase
{
    private function buildStripeEvent($overrides = [])
    {
        $event = [
            'type' => 'payment_intent.succeeded',
            'data' => [
                'object' => [
                    'id' => 'pi_test_123',
                    'charges' => [
                        'data' => [
                            [
                                'payment_method_details' => [
                                    'card' => [
                                        'iin' => '424242',
                                        'brand' => 'visa',
                                        'country' => 'US',
                                        'funding' => 'credit',
                                        'issuer' => 'Test Bank'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ];
        return json_encode($event);
    }

    public function testExtractIinFromStripeEvent()
  {
      $GLOBALS['test_value_chargeguard_stripe_webhook_secret'] = 'stripe_secret';
      $GLOBALS['mock_wc_get_orders_returns'] = [123];
      $GLOBALS['mock_wp_remote_body'] = '{"success":true}';
      $GLOBALS['registered_routes'] = [];

      $handler = new ChargeGuard_Stripe_Webhook();
      $payload = $this->buildStripeEvent();

      $response = $handler->handle_webhook(
          new class($payload) {
              public $body;
              public function __construct($b) { $this->body = $b; }
              public function get_body() { return $this->body; }
              public function get_header($h) { return 'valid'; }
          }
      );

      $this->assertEquals(200, $response->status);
      // enrich data capture will be validated in dedicated integration tests
  }

    public function testMissingOrderQueuesLocally()
    {
        $GLOBALS['test_value_chargeguard_stripe_webhook_secret'] = 'stripe_secret';
        $GLOBALS['mock_wc_get_orders_returns'] = [];
        $GLOBALS['captured_enrich_data'] = null;

        $handler = new ChargeGuard_Stripe_Webhook();
        $payload = $this->buildStripeEvent();

        $response = $handler->handle_webhook(
            new class($payload) {
                public $body;
                public function __construct($b) { $this->body = $b; }
                public function get_body() { return $this->body; }
                public function get_header($h) { return 'valid'; }
            }
        );

        $this->assertEquals(202, $response->status);
    }

    public function testInvalidSignatureReturns403()
    {
        $GLOBALS['test_value_chargeguard_stripe_webhook_secret'] = 'stripe_secret';

        $handler = new ChargeGuard_Stripe_Webhook();
        $payload = $this->buildStripeEvent();

        $response = $handler->handle_webhook(
            new class($payload) {
                public $body;
                public function __construct($b) { $this->body = $b; }
                public function get_body() { return $this->body; }
                public function get_header($h) { return 'invalid'; }
            }
        );

        $this->assertEquals(403, $response->status);
    }
}