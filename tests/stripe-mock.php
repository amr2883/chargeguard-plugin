<?php
namespace Stripe;

class Webhook
{
    public static function constructEvent($payload, $sig_header, $secret)
    {
        if ($sig_header === 'invalid') {
            throw new \Exception('Invalid signature');
        }
        return json_decode($payload);
    }
}