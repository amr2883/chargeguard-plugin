<?php
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/mocks.php';

require_once __DIR__ . '/../includes/class-api-client.php';
require_once __DIR__ . '/../includes/class-stripe-webhook.php';

class StripeWebhookTest extends TestCase
{
    public function testRestRouteIsRegistered()
    {
        $GLOBALS['registered_routes'] = [];
        new ChargeGuard_Stripe_Webhook();

        $this->assertArrayHasKey(
            'chargeguard/v1/stripe-webhook',
            $GLOBALS['registered_routes']
        );
    }
}