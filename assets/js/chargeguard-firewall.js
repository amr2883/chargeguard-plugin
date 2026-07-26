/**
 * ChargeGuard Device Fingerprint – JavaScript خفيف بدون تبعيات خارجية.
 *
 * - يحسب بصمة جهاز من خصائص المتصفح العامة
 * - يحفظها في كوكي الجلسة
 * - يستعلم من الخادم Ajax لفحص الحظر
 * - إذا حُظر، يمنع الوصول إلى الدفع ويعرض رسالة
 *
 * TRUST BOUNDARY WARNING: everything computed in this file is
 * client-side and unsigned by design — a visitor can override the
 * fingerprint value entirely (browser console, tampered request, or
 * simply clearing cookies for a fresh identity on the next load). This
 * script provides a fast first-line heuristic signal only. Do not add
 * logic here that treats a blocked/allowed decision from this
 * fingerprint as final; the server's cloud risk API call is the
 * authoritative check (see includes/class-dynamic-firewall.php).
 *
 * @since 1.0.0
 */

(function($) {
    'use strict';

    /**
     * توليد بصمة بسيطة من خصائص المتصفح.
     * @return {string} بصمة فريدة (نسبياً) تبدأ بـ "fp_"
     */
    /**
     * تجميع كل مكونات البصمة الخام في نص واحد.
     * يضيف WebGL وخصائص العتاد لأنها تصمد أمام تغيير User-Agent،
     * بخلاف نطاق ثنائيات المتصفح وحدها.
     * @return {string} النص الخام قبل الهاش.
     */
    function buildRawComponents() {
        var nav = window.navigator;
        var screen = window.screen;
        var tz = '';
        try {
            tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        } catch (e) {
            tz = '';
        }

        var components = [
            nav.userAgent,
            nav.language,
            screen.colorDepth,
            screen.pixelDepth,
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset(),
            tz,
            nav.hardwareConcurrency || '',
            nav.deviceMemory || '',
            nav.platform || '',
            nav.maxTouchPoints || 0,
            getCanvasFingerprint(),
            getWebGLFingerprint()
        ];

        return components.join('###');
    }

    /**
     * هاش djb2 احتياطي — يُستخدم فقط إذا لم تتوفر Web Crypto API
     * (سياق غير آمن أو متصفح قديم جداً). أضعف من SHA-256 عمداً،
     * لذلك يُعلَّم بادئة مختلفة (fp1_) ليعرف الخادم مستوى الثقة.
     * @param {string} str
     * @return {number}
     */
    function legacyHash(str) {
        var hash = 0;
        for (var i = 0; i < str.length; i++) {
            var char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0;
        }
        return hash;
    }

    /**
     * حساب البصمة النهائية عبر SHA-256 (Web Crypto API) مع تراجع
     * إلى djb2 عند عدم التوفر. غير متزامن بالضرورة (crypto.subtle
     * يعيد Promise)، لكن لا يؤخر عرض صفحة الدفع لأنه لا يحجب DOM.
     * @param {string} raw
     * @param {function(string)} callback
     */
    function computeFingerprint(raw, callback) {
        if (window.crypto && window.crypto.subtle && window.isSecureContext) {
            try {
                var enc = new TextEncoder();
                window.crypto.subtle.digest('SHA-256', enc.encode(raw)).then(function(buf) {
                    var bytes = new Uint8Array(buf);
                    var hex = '';
                    for (var i = 0; i < bytes.length; i++) {
                        hex += bytes[i].toString(16).padStart(2, '0');
                    }
                    callback('fp2_' + hex);
                }).catch(function() {
                    callback('fp1_' + Math.abs(legacyHash(raw)).toString(16));
                });
                return;
            } catch (e) {
                // يتابع إلى المسار الاحتياطي أدناه
            }
        }
        callback('fp1_' + Math.abs(legacyHash(raw)).toString(16));
    }

    /**
     * محاولة توليد بصمة Canvas (إذا كان مدعوماً).
     * @return {string} هيكس رمز canvas فريد نسبياً.
     */
    function getCanvasFingerprint() {
        try {
            var canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            var ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(10, 5, 50, 40);   // خلفية ملونة
            ctx.fillStyle = '#069';
            ctx.fillText('ChargeGuard', 20, 20); // نص
            var dataURI = canvas.toDataURL();
            return dataURI.substring(dataURI.length - 50); // آخر 50 حرف كمميز
        } catch (e) {
            return 'canvas_na';
        }
    }

    /**
     * بصمة WebGL (vendor/renderer) — تعكس عتاد/تعريف GPU الفعلي،
     * وتصمد أمام تدوير User-Agent على عكس بقية الحقول النصية.
     * لا تتطلب إذناً من المستخدم ولا استدعاءً غير متزامن.
     * @return {string}
     */
    function getWebGLFingerprint() {
        try {
            var canvas = document.createElement('canvas');
            var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) {
                return 'webgl_na';
            }
            var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (!debugInfo) {
                return 'webgl_no_debug';
            }
            var vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            return vendor + '~' + renderer;
        } catch (e) {
            return 'webgl_err';
        }
    }

    $(document).ready(function() {
        var raw = buildRawComponents();

        computeFingerprint(raw, function(fp) {
            // TRUST BOUNDARY WARNING: this cookie is plain, unsigned
            // client-side output — anyone with devtools can run
            // `document.cookie = 'chargeguard_fp=anything'` and replace
            // it, or simply clear cookies to get a fresh one. Never treat
            // chargeguard_fp, server-side or here, as a verified device
            // identity; it is a fast heuristic signal only. The
            // authoritative block/allow decision is made server-side by
            // the cloud risk API (see ChargeGuard_Dynamic_Firewall::
            // intercept_checkout() / intercept_checkout_block() in
            // includes/class-dynamic-firewall.php), which combines this
            // signal with others that are not client-forgeable.
            //
            // Secure فقط على HTTPS الفعلي، لتجنب فقد الكوكي بصمت في بيئات http محلية
            var secureFlag = (window.location.protocol === 'https:') ? '; Secure' : '';
            document.cookie = 'chargeguard_fp=' + fp + '; path=/; SameSite=Lax' + secureFlag;

            // إعلام الخادم وفحص الحظر
            $.post(chargeguard_fw.ajax_url, {
                action: 'chargeguard_check_fp',
                fingerprint: fp,
                nonce: chargeguard_fw.nonce
            }, function(response) {
                if (response.success && response.data.blocked) {
                    // Show a clear message in place of the checkout form
                    var checkoutForm = $('form.checkout');
                    if (checkoutForm.length) {
                        var message = '<div class="woocommerce-error" style="padding:20px; text-align:center; font-size:1.2em;">' +
                            'Sorry, your order cannot be processed. Please contact support.' +
                            '</div>';
                        checkoutForm.replaceWith(message);
                    }
                }
            }).fail(function() {
                // الفشل في الاتصال = لا نوقف التدفق (منعاً للإيجابيات الخاطئة)
            });
        });
    });
})(jQuery);