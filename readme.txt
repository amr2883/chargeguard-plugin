=== ChargeGuard - WooCommerce Card Testing Prevention ===
Contributors: Amr453
Tags: card testing, fraud prevention, woocommerce security, chargeback protection, bot detection
Requires at least: 6.0
Tested up to: 6.5
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Stop automated card testing bots from draining your wallet and trashing your store's database. Blocks fraud in real-time before an order is created.

== Description ==

ChargeGuard protects your WooCommerce store from the devastating impact of automated card testing attacks.

Every day, thousands of bots scan online stores to test stolen credit card numbers. These bots don't just try once – they hammer your checkout with hundreds of fake orders in minutes. The result? Your payment gateway charges you fees for every attempt, your database fills with failed orders, and your store's reputation with payment providers like Stripe and PayPal is put at risk.

ChargeGuard is a smart, multi-layered defense system built specifically for WooCommerce. Unlike traditional captcha solutions that slow down real customers or security plugins that miss API attacks, ChargeGuard intercepts and evaluates every checkout attempt before an order is created.

**Key Features:**
* **Real-Time API Protection**: Blocks fraud at both the classic checkout and the new WooCommerce Store API.
* **Intelligent Risk Scoring**: Analyzes email reputation, IP intelligence, and device fingerprinting to make accurate decisions.
* **Automatic Escalation**: Repeat offenders are automatically added to a permanent blacklist and completely locked out of your checkout page.
* **Zero Customer Friction**: Legitimate customers never see a captcha or experience any delay. Only fraud is blocked.
* **Developer Friendly**: Simple API key setup with powerful customization options for developers.

== Installation ==

1. Upload the `woocommerce-chargeguard` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to the **WooCommerce > Settings > ChargeGuard** page and enter your API Key and Merchant ID.
4. The firewall is now active and protecting your checkout.

== Frequently Asked Questions ==

= How does the plugin stop card testing? =

Before WooCommerce processes a checkout, the plugin sends a risk assessment to the ChargeGuard API. It analyzes the customer's IP address, email reputation, device fingerprint, and behavioral signals. If the order is identified as part of a card testing attack, it is blocked instantly.

= Does it slow down my checkout page? =

No. The risk assessment happens in the background in milliseconds. Your genuine customers won't notice any difference.

= What happens when a fraudster is blocked? =

They see a clear error message on the checkout page. Behind the scenes, their device fingerprint is tracked. After repeated attempts, they are permanently banned and shown a blocking page with no access to the checkout form.

= Is this compatible with my payment gateway? =

Yes. ChargeGuard works at the WooCommerce level, before your payment gateway is called. It is fully compatible with Stripe, PayPal, and all major gateways.

= Where is my data processed? =

The risk analysis is performed by the ChargeGuard cloud API. Only non-sensitive order metadata is transmitted. See our Privacy Policy for details.

== Screenshots ==

1. The ChargeGuard settings page in WooCommerce.
2. A blocked fraud order attempt visible in the order notes.
3. The real-time dashboard showing detailed attack analytics.

== Changelog ==

= 1.0.0 =
* Initial release with multi-layer fraud prevention.

== Upgrade Notice ==

= 1.0.0 =
Initial release.

== Privacy ==

This plugin connects to the ChargeGuard API, an external service provided by the ChargeGuard team, to perform real-time fraud risk assessment. During checkout, the following non-personal order data is transmitted for analysis:

* Customer IP address
* Customer email address (hashed)
* Order total
* A unique, randomly generated device fingerprint

This data is used exclusively for fraud prevention and is not shared with any third party. The data is subject to the ChargeGuard Terms of Service and Privacy Policy.

* [Terms of Service](https://chargeguard.app/terms)
* [Privacy Policy](https://chargeguard.app/privacy)

== Get Early Access for Free ==

We are looking for 10 WooCommerce store owners to join our Early Access Program. You will receive:
- Free access to ChargeGuard API for 3 months.
- Priority support and direct line to the development team.
- Influence the product roadmap.

[Join the Early Access Program](https://chargeguard.app/early-access)