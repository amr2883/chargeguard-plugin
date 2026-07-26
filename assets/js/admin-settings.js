(function($) {
    const nonce        = chargeguardAdmin.nonce;   // shared nonce — read-only AJAX actions only
    const nonces       = chargeguardAdmin.nonces;   // per-action nonces — required for every state-changing AJAX call below
    const cgCurrentIp  = chargeguardAdmin.currentIp;
    const cgMerchantId = chargeguardAdmin.merchantId;

    // ── Helper: HTML Escape ──────────────────────────────────
    function escHtml(str) {
        return String(str)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // ── Helper: Render Table ─────────────────────────────────
    function renderTable(entries, wrapId, listType) {
        const $wrap = $('#' + wrapId);
        if (!entries || entries.length === 0) {
            $wrap.html('<p style="color:#999;font-size:13px;text-align:center;padding:20px 0;">No entries yet.</p>');
            return;
        }
        let html = '<table style="width:100%;border-collapse:collapse;font-size:13px;">' +
            '<thead><tr style="border-bottom:2px solid #f0f0f0;">' +
            '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;width:80px;">Type</th>' +
            '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;">Value</th>' +
            '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;">Note</th>' +
            '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;width:90px;">Added</th>' +
            '<th style="width:32px;"></th></tr></thead><tbody>';

        entries.forEach(function(e) {
            const isExpired = e.expiresAt && new Date(e.expiresAt) < new Date();
            const dateStr   = new Date(e.createdAt).toLocaleDateString('en-GB', { day:'2-digit', month:'short' });
            const valStyle  = isExpired ? 'color:#999;text-decoration:line-through;' : 'font-family:monospace;';
            html += '<tr style="border-bottom:1px solid #f8f8f8;">' +
                '<td style="padding:9px 4px;"><span style="background:#f1f5f9;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600;color:#475569;">' + escHtml(e.type) + '</span></td>' +
                '<td style="padding:9px 4px;' + valStyle + '">' + escHtml(e.value) + (isExpired ? ' <span style="color:#f59e0b;font-size:11px;">(expired)</span>' : '') + '</td>' +
                '<td style="padding:9px 4px;color:#94a3b8;">' + (e.reason ? escHtml(e.reason) : '—') + '</td>' +
                '<td style="padding:9px 4px;color:#94a3b8;">' + dateStr + '</td>' +
                '<td style="padding:9px 4px;text-align:center;"><button class="cg-delete-entry" data-id="' + escHtml(e.id) + '" data-list="' + listType + '" title="Remove" style="background:none;border:none;cursor:pointer;color:#fca5a5;font-size:16px;padding:2px 6px;border-radius:4px;">×</button></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
        $wrap.html(html);
    }

    // ── Load Whitelist ───────────────────────────────────────
    function loadWhitelist() {
        $('#cg-wl-table-wrap').html('<p style="color:#999;font-size:13px;">Loading…</p>');
        $.post(ajaxurl, {
            action: 'chargeguard_whitelist_get',
            nonce:  nonce,
            merchantId: cgMerchantId,
        }, function(res) {
            if (res.success) {
                renderTable(res.data.entries, 'cg-wl-table-wrap', 'whitelist');
                if (res.data.entries && res.data.entries.length > 0) {
                    $('#cg-whitelist-onboarding').hide();
                }
            }
        });
    }

    // ── Load Blacklist ───────────────────────────────────────
    function loadBlacklist() {
        $('#cg-bl-table-wrap').html('<p style="color:#999;font-size:13px;">Loading…</p>');
        $.post(ajaxurl, {
            action: 'chargeguard_blacklist_get',
            nonce:  nonce,
            merchantId: cgMerchantId,
        }, function(res) {
            if (res.success) {
                renderTable(res.data.entries, 'cg-bl-table-wrap', 'blacklist');
            }
        });
    }

    // ── Tab Switcher ─────────────────────────────────────────
    $(document).on('click', '.cg-ac-tab', function() {
        const tab = $(this).data('tab');
        $('.cg-ac-tab').css({ color:'#999', borderBottomColor:'transparent' });
        $(this).css({
            color: tab === 'whitelist' ? '#16a34a' : '#dc2626',
            borderBottomColor: tab === 'whitelist' ? '#16a34a' : '#dc2626'
        });
        $('#cg-tab-whitelist, #cg-tab-blacklist').hide();
        $('#cg-tab-' + tab).show();
        if (tab === 'whitelist') loadWhitelist();
        else loadBlacklist();
    });

    // ── Add My IP ────────────────────────────────────────────
    $('#cg-add-my-ip').on('click', function() {
        const $btn = $(this);
        $btn.prop('disabled', true).text('Adding…');
        $.post(ajaxurl, {
            action: 'chargeguard_whitelist_add',
            nonce:  nonces.whitelistAdd,
            type:   'IP',
            value:  cgCurrentIp,
            reason: 'My admin IP — added automatically',
        }, function(res) {
            if (res.success) {
                $('#cg-whitelist-onboarding').slideUp(300);
                loadWhitelist();
            } else {
                $btn.prop('disabled', false).text('+ Add My IP');
            }
        });
    });

    // ── Dynamic Placeholder ──────────────────────────────────
    const wlPlaceholders = { IP:'e.g. 197.12.34.56', EMAIL:'e.g. john@mystore.com', BIN:'e.g. 411111 (first 6 digits)' };
    const blPlaceholders = { IP:'e.g. 45.33.32.156', EMAIL:'e.g. fraud@example.com', BIN:'e.g. 411111 (first 6 digits)', DEVICE_FINGERPRINT:'Device fingerprint ID' };
    $('#cg-wl-type').on('change', function() { $('#cg-wl-value').attr('placeholder', wlPlaceholders[$(this).val()] || ''); });
    $('#cg-bl-type').on('change', function() { $('#cg-bl-value').attr('placeholder', blPlaceholders[$(this).val()] || ''); });

    // ── Add to Whitelist ─────────────────────────────────────
    $('#cg-wl-add').on('click', function() {
        const type   = $('#cg-wl-type').val();
        const value  = $('#cg-wl-value').val().trim();
        const reason = $('#cg-wl-reason').val().trim();
        const $msg   = $('#cg-wl-message');
        if (!value) {
            $msg.removeClass('success').addClass('error').text('Please enter a value.').show();
            return;
        }
        $(this).prop('disabled', true).text('Adding…');
        $msg.hide().removeClass('error success');
        $.post(ajaxurl, {
            action: 'chargeguard_whitelist_add',
            nonce: nonces.whitelistAdd, type, value, reason,
        }, function(res) {
            if (res.success) {
                $('#cg-wl-value, #cg-wl-reason').val('');
                $msg.removeClass('error').addClass('success').text('✓ Added to safe list.').show();
                loadWhitelist();
                setTimeout(function() { $msg.fadeOut(); }, 3000);
            } else {
                $msg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Failed to add. Try again.').show();
            }
            $('#cg-wl-add').prop('disabled', false).text('+ Add to Safe List');
        });
    });

    // ── Add to Blacklist ─────────────────────────────────────
    $('#cg-bl-add').on('click', function() {
        const type   = $('#cg-bl-type').val();
        const value  = $('#cg-bl-value').val().trim();
        const reason = $('#cg-bl-reason').val().trim();
        const $msg   = $('#cg-bl-message');
        if (!value) {
            $msg.removeClass('success').addClass('error').text('Please enter a value.').show();
            return;
        }
        if (type === 'IP' && value === cgCurrentIp) {
            if (!window.confirm('⚠️ Warning\n\nThis is your current admin IP address.\nBlocking it may disrupt your store\'s connection to ChargeGuard.\n\nAre you absolutely sure?')) return;
        }
        $(this).prop('disabled', true).text('Blocking…');
        $msg.hide().removeClass('error success');
        $.post(ajaxurl, {
            action: 'chargeguard_blacklist_add',
            nonce: nonces.blacklistAdd, type, value, reason,
        }, function(res) {
            if (res.success) {
                $('#cg-bl-value, #cg-bl-reason').val('');
                $msg.removeClass('error').addClass('success').text('✓ Added to blocked list.').show();
                loadBlacklist();
                setTimeout(function() { $msg.fadeOut(); }, 3000);
            } else {
                $msg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Failed to add. Try again.').show();
            }
            $('#cg-bl-add').prop('disabled', false).text('🚫 Block This');
        });
    });

    // ── Delete Entry ─────────────────────────────────────────
    $(document).on('click', '.cg-delete-entry', function() {
        const id          = $(this).data('id');
        const listType    = $(this).data('list');
        const action      = listType === 'whitelist' ? 'chargeguard_whitelist_delete' : 'chargeguard_blacklist_delete';
        const deleteNonce = listType === 'whitelist' ? nonces.whitelistDelete : nonces.blacklistDelete;
        const $row        = $(this).closest('tr');
        $row.fadeOut(200, function() { $(this).remove(); });
        $.post(ajaxurl, { action, nonce: deleteNonce, id }, function(res) {
            if (!res.success) {
                if (listType === 'whitelist') loadWhitelist();
                else loadBlacklist();
            }
        });
    });

    // ── Managed Stores (Agency) ──────────────────────────────
    function renderStoresTable(stores) {
        const $wrap = $('#cg-store-table-wrap');
        const cleanupMode = $('#cg-managed-stores').data('mode') === 'cleanup';
        if (!stores || stores.length === 0) {
            $wrap.html('<p style="color:#999;font-size:13px;text-align:center;padding:20px 0;">No stores added yet.</p>');
            return;
        }
        let html = '<table style="width:100%;border-collapse:collapse;font-size:13px;">' +
            '<thead><tr style="border-bottom:2px solid #f0f0f0;">' +
            '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;">Domain</th>' +
            '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;">Label</th>' +
            '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;width:80px;">Status</th>' +
            '<th style="width:150px;"></th></tr></thead><tbody>';

        stores.forEach(function(s) {
            const statusHtml = s.isActive
                ? '<span style="color:#16a34a;font-weight:600;">● Active</span>'
                : '<span style="color:#999;">○ Inactive</span>';
            html += '<tr style="border-bottom:1px solid #f8f8f8;" data-id="' + escHtml(s.id) + '">' +
                '<td style="padding:9px 4px;font-family:monospace;">' + escHtml(s.normalizedDomain) + '</td>' +
                '<td style="padding:9px 4px;">' +
                    '<span class="cg-store-label-text">' + (s.label ? escHtml(s.label) : '—') + '</span>' +
                '</td>' +
                '<td style="padding:9px 4px;">' + statusHtml + '</td>' +
                '<td style="padding:9px 4px;text-align:right;white-space:nowrap;">' +
                    (cleanupMode ? '' : '<button class="cg-store-rename" data-id="' + escHtml(s.id) + '" data-label="' + escHtml(s.label || '') + '" style="background:none;border:none;cursor:pointer;color:#2563eb;font-size:12px;margin-right:8px;">Rename</button>') +
                    (s.isActive
                        ? '<button class="cg-store-deactivate" data-id="' + escHtml(s.id) + '" style="background:none;border:none;cursor:pointer;color:#dc2626;font-size:12px;">Deactivate</button>'
                        : (cleanupMode ? '<span style="color:#999;font-size:12px;">Inactive</span>' : '<button class="cg-store-reactivate" data-id="' + escHtml(s.id) + '" style="background:none;border:none;cursor:pointer;color:#16a34a;font-size:12px;">Reactivate</button>')) +
                '</td></tr>';
        });
        html += '</tbody></table>';
        $wrap.html(html);
    }

    function loadStores() {
        $('#cg-store-table-wrap').html('<p style="color:#999;font-size:13px;">Loading…</p>');
        $.post(ajaxurl, { action: 'chargeguard_stores_get', nonce: nonce }, function(res) {
            if (res.success) {
                renderStoresTable(res.data.stores);
            } else {
                $('#cg-store-table-wrap').html('<p style="color:#dc2626;font-size:13px;">' + escHtml((res.data && res.data.message) || 'Failed to load stores.') + '</p>');
            }
        });
    }

    $('#cg-store-add').on('click', function() {
        const storeUrl = $('#cg-store-url').val().trim();
        const label    = $('#cg-store-label').val().trim();
        const $msg     = $('#cg-store-message');
        if (!storeUrl) {
            $msg.removeClass('success').addClass('error').text('Please enter a store domain.').show();
            return;
        }
        $(this).prop('disabled', true).text('Adding…');
        $msg.hide().removeClass('error success');
        $.post(ajaxurl, {
            action: 'chargeguard_store_add',
            nonce: nonces.storeAdd,
            store_url: storeUrl,
            label: label,
        }, function(res) {
            if (res.success) {
                $('#cg-store-url, #cg-store-label').val('');
                $msg.removeClass('error').addClass('success')
                    .text(res.data.reactivated ? '✓ Store reactivated.' : '✓ Store added.').show();
                loadStores();
                setTimeout(function() { $msg.fadeOut(); }, 3000);
            } else {
                $msg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Failed to add store.').show();
            }
            $('#cg-store-add').prop('disabled', false).text('+ Add Store');
        });
    });

    $(document).on('click', '.cg-store-rename', function() {
        const id           = $(this).data('id');
        const currentLabel = $(this).data('label') || '';
        const newLabel     = window.prompt('Rename this store:', currentLabel);
        if (newLabel === null || newLabel.trim() === currentLabel.trim()) return;
        $.post(ajaxurl, {
            action: 'chargeguard_store_rename',
            nonce: nonces.storeRename,
            id: id,
            label: newLabel.trim(),
        }, function(res) {
            if (res.success) loadStores();
            else alert((res.data && res.data.message) || 'Failed to rename store.');
        });
    });

    $(document).on('click', '.cg-store-deactivate', function() {
        const id = $(this).data('id');
        if (!window.confirm('Deactivate this store? Requests from this domain will be rejected until reactivated.')) return;
        $.post(ajaxurl, {
            action: 'chargeguard_store_deactivate',
            nonce: nonces.storeDeactivate,
            id: id,
        }, function(res) {
            if (res.success) loadStores();
            else alert((res.data && res.data.message) || 'Failed to deactivate store.');
        });
    });

    $(document).on('click', '.cg-store-reactivate', function() {
        const id = $(this).data('id');
        $.post(ajaxurl, {
            action: 'chargeguard_store_reactivate',
            nonce: nonces.storeDeactivate,
            id: id,
        }, function(res) {
            if (res.success) loadStores();
            else alert((res.data && res.data.message) || 'Failed to reactivate store.');
        });
    });

    // ── تحميل تلقائي عند فتح الصفحة ─────────────────────────
    if (chargeguardAdmin.isConnected) {
        loadWhitelist();
        if ($('#cg-managed-stores').length) loadStores();
    }

    // ── Connect (device-code-style polling flow) ──────────────
    let cgTurnstileToken = '';
    window.cgTurnstileCallback = function(token) { cgTurnstileToken = token; };

    const CG_POLL_INTERVAL_MS = 3000;
    const CG_POLL_MAX_MS      = 16 * 60 * 1000; // slightly past backend's 15-min token expiry
    let cgPollTimer  = null;
    let cgPollStopAt = 0;

    function cgShowPendingUI() {
        $('#cg-connect-form').hide();
        $('#cg-connect-pending').show();
    }

    function cgShowFormUI() {
        $('#cg-connect-pending').hide();
        $('#cg-connect-form').show();
        $('#cg-step-1').removeClass('done').addClass('active');
        $('#cg-step-2').removeClass('active done');
    }

    function cgStartPolling() {
        cgPollStopAt = Date.now() + CG_POLL_MAX_MS;
        cgShowPendingUI();
        $('#cg-step-1').removeClass('active').addClass('done');
        $('#cg-step-2').addClass('active');
        clearTimeout(cgPollTimer);
        cgPollOnce();
    }

    function cgPollOnce() {
        if (Date.now() > cgPollStopAt) {
            $('#cg-message').removeClass('success').addClass('error')
                .text('This connection attempt timed out. Please try again.').show();
            cgShowFormUI();
            return;
        }

        $.post(ajaxurl, { action: 'chargeguard_connect_poll', nonce: nonce }, function(res) {
            const status = res.data && res.data.status;

            if (status === 'active') {
                $('#cg-step-2').removeClass('active').addClass('done');
                $('#cg-step-3').addClass('active done');
                const $msg = $('#cg-message');
                if (res.data.selfTestOk === false) {
                    $msg.removeClass('success').addClass('error')
                        .text('⚠️ ' + (res.data.selfTestError || 'Connected, but signature verification failed.')).show();
                } else {
                    $msg.removeClass('error').addClass('success')
                        .text('✅ Connected successfully! Reloading…').show();
                }
                setTimeout(() => location.reload(), 1500);
                return;
            }

            if (status === 'expired') {
                $('#cg-message').removeClass('success').addClass('error')
                    .text('The confirmation link expired before it was clicked. Please try again.').show();
                cgShowFormUI();
                return;
            }

            if (status === 'failed') {
                $('#cg-message').removeClass('success').addClass('error')
                    .text((res.data && res.data.message) || 'Connection failed. Please try again.').show();
                cgShowFormUI();
                return;
            }

            // 'pending' — keep waiting
            cgPollTimer = setTimeout(cgPollOnce, CG_POLL_INTERVAL_MS);
        }).fail(function() {
            // Network hiccup — keep polling rather than give up on one failure.
            cgPollTimer = setTimeout(cgPollOnce, CG_POLL_INTERVAL_MS);
        });
    }

    // A connect request was already in flight when this page loaded
    // (e.g. the merchant refreshed while waiting for the email) —
    // resume polling immediately instead of showing the form again.
    if (chargeguardAdmin.hasPendingConnect) {
        cgStartPolling();
    }

    $('#cg-connect-btn').on('click', function() {
        const email = $('#cg-email-input').val().trim();
        const $btn  = $(this);
        const $msg  = $('#cg-message');

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            $msg.removeClass('success').addClass('error').text('Please enter a valid email address.').show();
            return;
        }

        if (!cgTurnstileToken) {
            $msg.removeClass('success').addClass('error').text('Please wait a moment for the security check to finish, then try again.').show();
            return;
        }

        $btn.prop('disabled', true).html('<span class="cg-spinner"></span> Sending…');
        $msg.hide().removeClass('error success');

        $.post(ajaxurl, {
            action:         'chargeguard_connect',
            nonce:          nonces.connect,
            email:          email,
            turnstileToken: cgTurnstileToken,
        }, function(res) {
            if (res.success) {
                cgStartPolling();
            } else {
                $msg.removeClass('success').addClass('error').text(res.data.message).show();
                $btn.prop('disabled', false).html('🔌 Connect ChargeGuard');
            }
        }).fail(function() {
            $msg.removeClass('success').addClass('error')
                .text('Connection failed. Please try again.').show();
            $btn.prop('disabled', false).html('🔌 Connect ChargeGuard');
        });
    });

    // ── Verify Key ───────────────────────────────────────────────
    $('#cg-verify-key-btn').on('click', function() {
        const $btn    = $(this);
        const $status = $('#cg-key-status');

        $btn.prop('disabled', true).text('Verifying…');
        $status.hide().css({ background: '', border: '', color: '' });

        $.post(ajaxurl, {
            action: 'chargeguard_verify_key',
            nonce:  nonce,
        }, function(res) {
            if (res.success) {
                $status.css({
                    background: '#f0fdf4',
                    border:     '1px solid #bbf7d0',
                    color:      '#16a34a',
                }).text('✓ API key is valid and active.').show();
            } else {
                $status.css({
                    background: '#fef2f2',
                    border:     '1px solid #fecaca',
                    color:      '#dc2626',
                }).text('✗ ' + (res.data.message || 'Invalid API key. Please reconnect.')).show();
            }
        }).fail(function() {
            $status.css({
                background: '#fef2f2',
                border:     '1px solid #fecaca',
                color:      '#dc2626',
            }).text('✗ Could not reach server. Try again.').show();
        }).always(function() {
            $btn.prop('disabled', false).text('Verify Key');
        });
    });

    // ── Check for Updates ───────────────────────────────────────
    $('#cg-check-updates-btn').on('click', function() {
        const $btn    = $(this);
        const $status = $('#cg-key-status');

        $btn.prop('disabled', true).text('Checking…');
        $status.hide().css({ background: '', border: '', color: '' });

        $.post(ajaxurl, {
            action: 'chargeguard_check_for_updates',
            nonce:  nonce,
        }, function(res) {
            if (res.success) {
                $status.css({
                    background: '#f0fdf4',
                    border:     '1px solid #bbf7d0',
                    color:      '#16a34a',
                }).text('✓ Checked for updates. If a new version is available, it will appear on the Plugins page.').show();
            } else {
                $status.css({
                    background: '#fef2f2',
                    border:     '1px solid #fecaca',
                    color:      '#dc2626',
                }).text('✗ ' + ((res.data && res.data.message) || 'Failed to check for updates.')).show();
            }
        }).fail(function() {
            $status.css({
                background: '#fef2f2',
                border:     '1px solid #fecaca',
                color:      '#dc2626',
            }).text('✗ Could not reach server. Try again.').show();
        }).always(function() {
            $btn.prop('disabled', false).text('Check for Updates');
        });
    });

    // ── Disconnect ───────────────────────────────────────────────
    $('#cg-disconnect-btn').on('click', function() {
        if (!confirm('Are you sure you want to disconnect ChargeGuard?')) return;
        const $btn = $(this);
        $btn.prop('disabled', true).text('Disconnecting…');

        $.post(ajaxurl, {
            action: 'chargeguard_disconnect',
            nonce:  nonces.disconnect,
        }, function(res) {
            if (res.success) location.reload();
        });
    });

    // ── Webhook ────────────────────────────────────────────────
    const $webhookUrl    = $('#cg-webhook-url');
    const $webhookMsg    = $('#cg-webhook-message');
    const $webhookStatus = $('#cg-webhook-status-text');
    const $webhookDot    = $('#cg-webhook-status-dot');
    let currentType      = 'slack';

    // Tab switcher
    $('.cg-webhook-tab').on('click', function() {
        currentType = $(this).data('type');
        $('.cg-webhook-tab').css({ background:'#fff', color:'#999' });
        $(this).css({ background:'#f0fdf4', color:'#16a34a' });
        // Update guide text
        const guides = {
            slack:  'Create an <strong>Incoming Webhook</strong> in Slack → paste the URL below.',
            discord: 'Create an <strong>Incoming Webhook</strong> in Discord → paste the URL below.',
            custom: 'Enter any HTTPS URL that accepts JSON POST requests.'
        };
        $('#cg-webhook-guide').html(guides[currentType] || guides.custom);
    });

    // Load saved settings on page load
    $.post(ajaxurl, { action: 'chargeguard_webhook_status', nonce }, function(res) {
        if (res.success) {
            const d = res.data;
            if (d.webhookUrl) {
                $webhookUrl.val(d.webhookUrl);
                currentType = d.webhookType || 'custom';
                $('.cg-webhook-tab').css({ background:'#fff', color:'#999' });
                const $tab = $('.cg-webhook-tab[data-type="' + currentType + '"]');
                if ($tab.length) $tab.css({ background:'#f0fdf4', color:'#16a34a' });
                else { currentType = 'custom'; $('.cg-webhook-tab[data-type="custom"]').css({ background:'#f0fdf4', color:'#16a34a' }); }
            }
            if (d.webhookLastStatus === 'success') {
                $webhookStatus.text('Last test: successful');
                $webhookDot.css({ background:'#16a34a' }).show();
            } else if (d.webhookLastStatus === 'failed') {
                $webhookStatus.text('Last test: failed (' + (d.webhookFailureCount || 0) + ' attempts)');
                $webhookDot.css({ background:'#dc2626' }).show();
            } else if (d.webhookUrl) {
                $webhookStatus.text('Saved — not tested yet');
                $webhookDot.css({ background:'#f59e0b' }).show();
            }
        }
    });

    // Save webhook
    $('#cg-webhook-save').on('click', function() {
        const url   = $webhookUrl.val().trim();
        const $btn  = $(this);
        if (!url) {
            $webhookMsg.removeClass('success').addClass('error').text('Please enter a webhook URL.').show();
            return;
        }
        if (!url.startsWith('https://')) {
            $webhookMsg.removeClass('success').addClass('error').text('Only HTTPS URLs are allowed.').show();
            return;
        }
        $btn.prop('disabled', true).text('Saving…');
        $webhookMsg.hide().removeClass('error success');
        $.post(ajaxurl, {
            action:       'chargeguard_webhook_save',
            nonce:        nonces.webhookSave,
            webhook_url:  url,
            webhook_type: currentType,
        }, function(res) {
            if (res.success) {
                $webhookMsg.removeClass('error').addClass('success').text('✓ Webhook saved.').show();
                $webhookStatus.text('Saved — not tested yet');
                $webhookDot.css({ background:'#f59e0b' }).show();
                setTimeout(function() { $webhookMsg.fadeOut(); }, 3000);
            } else {
                $webhookMsg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Failed to save.').show();
            }
            $btn.prop('disabled', false).text('💾 Save Webhook');
        });
    });

    // Test webhook
    $('#cg-webhook-test').on('click', function() {
        const $btn = $(this);
        $btn.prop('disabled', true).text('Testing…');
        $webhookMsg.hide().removeClass('error success');
        $.post(ajaxurl, {
            action: 'chargeguard_webhook_test',
            nonce:  nonce,
        }, function(res) {
            if (res.success) {
                $webhookMsg.removeClass('error').addClass('success').text('✓ Test notification sent! Check your channel.').show();
                $webhookStatus.text('Last test: successful');
                $webhookDot.css({ background:'#16a34a' }).show();
            } else {
                $webhookMsg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Test failed. Check your webhook URL.').show();
                $webhookStatus.text('Last test: failed');
                $webhookDot.css({ background:'#dc2626' }).show();
            }
            $btn.prop('disabled', false).text('📤 Send Test Notification');
        });
    });

    // ── PayPal Integration ────────────────────────────────────────
    let cgPpMode = $('#cg-pp-mode').val() || 'sandbox';

    // Guide arrow animation
    $('#cg-pp-guide').on('toggle', function() {
        $('#cg-pp-guide-arrow').css(
            'transform',
            this.open ? 'rotate(90deg)' : 'rotate(0deg)'
        );
    });

    // Mode toggle
    $(document).on('click', '.cg-pp-mode-btn', function() {
        cgPpMode = $(this).data('mode');
        $('#cg-pp-mode').val(cgPpMode);
        $('.cg-pp-mode-btn').css({ background: '#fff', color: '#999' });
        $(this).css({ background: '#f0fdf4', color: '#16a34a' });
    });

    // Copy Webhook URL
    $('#cg-pp-copy-url').on('click', function() {
        const url = $('code', '#cg-paypal-integration').first().text().trim();
        navigator.clipboard.writeText(url).then(function() {
            $('#cg-pp-copy-url').text('✓ Copied!');
            setTimeout(function() { $('#cg-pp-copy-url').text('📋 Copy'); }, 2000);
        });
    });

    // Save PayPal Settings
    $('#cg-pp-save').on('click', function() {
        const $btn    = $(this);
        const $msg    = $('#cg-pp-message');
        const secret  = $('#cg-pp-client-secret').val().trim();

        $btn.prop('disabled', true).text('Saving…');
        $msg.hide().removeClass('error success');

        const postData = {
            action:        'chargeguard_paypal_save',
            nonce:         nonces.paypalSave,
            client_id:     $('#cg-pp-client-id').val().trim(),
            webhook_id:    $('#cg-pp-webhook-id').val().trim(),
            mode:          cgPpMode,
            enabled:       $('#cg-pp-enabled').is(':checked') ? '1' : '0',
        };
        if (secret) postData.client_secret = secret;

        $.post(ajaxurl, postData, function(res) {
            if (res.success) {
                $msg.removeClass('error').addClass('success')
                    .text('✓ PayPal settings saved.').show();
                $('#cg-pp-client-secret').val('').attr('placeholder', '••••••••••••••••');
                setTimeout(function() { $msg.fadeOut(); }, 3000);
            } else {
                $msg.removeClass('success').addClass('error')
                    .text((res.data && res.data.message) || 'Failed to save.').show();
            }
            $btn.prop('disabled', false).text('💾 Save PayPal Settings');
        });
    });

    // Test PayPal Connection
    $('#cg-pp-test').on('click', function() {
        const $btn = $(this);
        const $msg = $('#cg-pp-message');
        $btn.prop('disabled', true).text('Testing…');
        $msg.hide().removeClass('error success');

        $.post(ajaxurl, {
            action: 'chargeguard_paypal_test',
            nonce:  nonce,
        }, function(res) {
            if (res.success) {
                $msg.removeClass('error').addClass('success')
                    .text((res.data && res.data.message) || '✓ Connected.').show();
            } else {
                $msg.removeClass('success').addClass('error')
                    .text((res.data && res.data.message) || 'Connection failed.').show();
            }
            $btn.prop('disabled', false).text('🔗 Test Connection');
        });
    });

    // ── Stripe Integration ────────────────────────────────────────

    $('#cg-st-copy-url').on('click', function() {
        const url = $('code', '#cg-stripe-integration').first().text().trim();
        navigator.clipboard.writeText(url).then(function() {
            $('#cg-st-copy-url').text('✓ Copied!');
            setTimeout(function() { $('#cg-st-copy-url').text('📋 Copy'); }, 2000);
        });
    });

    $('#cg-st-save').on('click', function() {
        const $btn          = $(this);
        const $msg          = $('#cg-st-message');
        const secretKey     = $('#cg-st-secret-key').val().trim();
        const webhookSecret = $('#cg-st-webhook-secret').val().trim();

        $btn.prop('disabled', true).text('Saving…');
        $msg.hide().removeClass('error success');

        const postData = {
            action:  'chargeguard_stripe_save',
            nonce:   nonces.stripeSave,
            enabled: $('#cg-st-enabled').is(':checked') ? '1' : '0',
        };
        if (secretKey)     postData.secret_key     = secretKey;
        if (webhookSecret) postData.webhook_secret = webhookSecret;

        $.post(ajaxurl, postData, function(res) {
            if (res.success) {
                $msg.removeClass('error').addClass('success')
                    .text('✓ Stripe settings saved.').show();
                $('#cg-st-secret-key').val('').attr('placeholder', '••••••••••••••••');
                $('#cg-st-webhook-secret').val('').attr('placeholder', '••••••••••••••••');
                setTimeout(function() { $msg.fadeOut(); }, 3000);
            } else {
                $msg.removeClass('success').addClass('error')
                    .text((res.data && res.data.message) || 'Failed to save.').show();
            }
            $btn.prop('disabled', false).text('💾 Save Stripe Settings');
        });
    });

    $('#cg-st-test').on('click', function() {
        const $btn = $(this);
        const $msg = $('#cg-st-message');
        $btn.prop('disabled', true).text('Testing…');
        $msg.hide().removeClass('error success');

        $.post(ajaxurl, {
            action: 'chargeguard_stripe_test',
            nonce:  nonce,
        }, function(res) {
            if (res.success) {
                $msg.removeClass('error').addClass('success')
                    .text((res.data && res.data.message) || '✓ Connected.').show();
            } else {
                $msg.removeClass('success').addClass('error')
                    .text((res.data && res.data.message) || 'Connection failed.').show();
            }
            $btn.prop('disabled', false).text('🔗 Test Connection');
        });
    });

    // ── Geo Risk Intelligence ─────────────────────────────────────
    const TIER_CONFIG = {
        critical: { emoji: '🛑', label: 'Extreme Risk',   color: '#dc2626', bg: '#fef2f2' },
        high:     { emoji: '⚠️', label: 'High Risk',      color: '#ea580c', bg: '#fff7ed' },
        medium:   { emoji: '🟡', label: 'Moderate Risk',  color: '#ca8a04', bg: '#fefce8' },
        elevated: { emoji: '🔵', label: 'Monitored',      color: '#2563eb', bg: '#eff6ff' },
    };

    const OVERRIDE_CONFIG = {
        smart:    { label: '● Smart',    color: '#16a34a', desc: 'Use ChargeGuard default' },
        allow:    { label: '○ Allow',    color: '#2563eb', desc: 'Remove country penalty'  },
        escalate: { label: '○ Escalate', color: '#ea580c', desc: 'Double country penalty'  },
    };

    let cgGeoCountries    = [];
    let cgPendingChange   = null;

    function cgGetEffectivePenalty(basePenalty, override) {
        if (override === 'allow')    return 0;
        if (override === 'escalate') return Math.min(basePenalty * 2, 20);
        return basePenalty;
    }

    function cgBuildImpactText(change) {
        const c        = change.country;
        const tierConf = TIER_CONFIG[c.tier] || TIER_CONFIG.elevated;
        const newPenalty = cgGetEffectivePenalty(c.basePenalty, change.newOverride);
        const oldPenalty = cgGetEffectivePenalty(c.basePenalty, change.currentOverride);

        if (change.newOverride === 'allow') {
            return tierConf.emoji + ' Removing the +' + c.basePenalty +
                ' pt risk penalty for <strong>' + escHtml(c.name) + '</strong>. ' +
                'All other fraud signals still apply.' +
                (c.tier === 'critical' ? ' <strong style="color:#dc2626;">⚠️ High-risk region — monitor chargebacks closely.</strong>' : '');
        }
        if (change.newOverride === 'escalate') {
            return '⬆️ Escalating <strong>' + escHtml(c.name) + '</strong> penalty from ' +
                oldPenalty + ' to <strong>' + newPenalty + ' pts</strong>. ' +
                'Transactions from this region will be scored more strictly.';
        }
        return '↩️ Restoring <strong>' + escHtml(c.name) +
            '</strong> to Smart default (' + c.basePenalty + ' pts).';
    }

    function cgRenderTierGroups(countries) {
        const byTier = {};
        countries.forEach(function(c) {
            if (!byTier[c.tier]) byTier[c.tier] = [];
            byTier[c.tier].push(c);
        });

        const tierOrder = ['critical', 'high', 'medium', 'elevated'];
        let html = '';

        tierOrder.forEach(function(tier) {
            if (!byTier[tier] || !byTier[tier].length) return;
            const tc = TIER_CONFIG[tier];
            html += '<div style="margin-bottom:16px;">';
            html += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:10px;">';
            html += '<span style="font-size:13px;font-weight:700;color:' + tc.color + ';">' +
                    tc.emoji + ' ' + tc.label + '</span>';
            html += '</div>';

            byTier[tier].forEach(function(c) {
                // c.code comes from the backend's chargeguard_geo_overrides_get
                // response — an external system this admin page trusts for
                // rendering, but not for HTML structure. Validate it against
                // the ISO-3166-1 alpha-2 shape before it's used anywhere
                // (id attribute, data-code attribute, cgGetFlag()) so a
                // compromised backend, MITM, or corrupted response can't
                // inject markup into the WordPress admin DOM.
                if (typeof c.code !== 'string' || !/^[A-Z]{2}$/i.test(c.code)) {
                    console.warn('ChargeGuard: skipping geo entry with invalid country code', c.code);
                    return;
                }
                const cur = c.currentOverride || 'smart';
                html += '<div style="display:flex;align-items:center;justify-content:space-between;' +
                        'padding:10px 12px;border-radius:8px;background:' + tc.bg + ';' +
                        'border:1px solid ' + tc.color + '22;margin-bottom:6px;flex-wrap:wrap;gap:8px;">';

                html += '<div style="display:flex;align-items:center;gap:8px;min-width:140px;">';
                html += '<span style="font-size:14px;">' + cgGetFlag(c.code) + '</span>';
                html += '<span style="font-size:13px;font-weight:600;color:#1e293b;">' +
                        escHtml(c.name) + '</span>';
                html += '<span id="cg-penalty-' + escHtml(c.code) + '" ' +
                        'style="font-size:11px;color:' + tc.color + ';background:' + tc.color + '15;' +
                        'padding:2px 6px;border-radius:4px;font-weight:600;">' +
                        '-' + cgGetEffectivePenalty(c.basePenalty, cur) + ' pts</span>';
                html += '</div>';

                html += '<div style="display:flex;gap:6px;">';
                ['smart', 'allow', 'escalate'].forEach(function(ov) {
                    const isActive = cur === ov;
                    const ovConf   = OVERRIDE_CONFIG[ov];
                    const btnColor = isActive ? ovConf.color : '#94a3b8';
                    const btnBg    = isActive ? ovConf.color + '15' : '#fff';
                    const border   = isActive ? ovConf.color : '#e2e8f0';
                    html += '<button class="cg-geo-radio" ' +
                            'data-code="' + escHtml(c.code) + '" ' +
                            'data-override="' + ov + '" ' +
                            'title="' + escHtml(ovConf.desc) + '" ' +
                            'style="padding:5px 10px;border-radius:6px;font-size:12px;font-weight:600;' +
                            'cursor:pointer;border:1px solid ' + border + ';' +
                            'background:' + btnBg + ';color:' + btnColor + ';">' +
                            (isActive ? '● ' : '○ ') + ov.charAt(0).toUpperCase() + ov.slice(1) +
                            '</button>';
                });
                html += '</div>';
                html += '</div>';
            });

            html += '</div>';
        });

        $('#cg-geo-tiers').html(html);
    }

    function cgGetFlag(code) {
        try {
            return code.toUpperCase().replace(/./g, function(c) {
                return String.fromCodePoint(c.charCodeAt(0) + 127397);
            });
        } catch(e) { return '🌐'; }
    }

    function cgUpdateSummary(countries) {
        const modified = countries.filter(function(c) { return c.currentOverride !== 'smart'; }).length;
        if (modified === 0) {
            $('#cg-override-count').text('All regions using Smart defaults');
        } else {
            $('#cg-override-count').text(modified + ' region' + (modified > 1 ? 's' : '') + ' customized');
        }
    }

    // تحميل البيانات
    if (chargeguardAdmin.isConnected) {
        $.post(ajaxurl, {
            action: 'chargeguard_geo_overrides_get',
            nonce:  nonce,
        }, function(res) {
            if (res.success) {
                cgGeoCountries = res.data.availableCountries || [];
                cgRenderTierGroups(cgGeoCountries);
                cgUpdateSummary(cgGeoCountries);
            } else {
                $('#cg-geo-tiers').html('<p style="color:#dc2626;font-size:13px;">Failed to load geo settings.</p>');
            }
        });
    }

    // Radio button click
    $(document).on('click', '.cg-geo-radio', function() {
        const code        = $(this).data('code');
        const newOverride = $(this).data('override');
        const country     = cgGeoCountries.find(function(c) { return c.code === code; });
        if (!country) return;

        const currentOverride = country.currentOverride || 'smart';
        if (currentOverride === newOverride) return;

        cgPendingChange = { code, newOverride, currentOverride, country };

        $('#cg-geo-impact-text').html(cgBuildImpactText(cgPendingChange));
        $('#cg-geo-impact').show();
        $('#cg-geo-message').hide().removeClass('error success');
    });

    // Apply Change
    $('#cg-geo-confirm').on('click', function() {
        if (!cgPendingChange) return;
        const $btn = $(this);
        $btn.prop('disabled', true).text('Saving…');

        $.post(ajaxurl, {
            action:       'chargeguard_geo_override_save',
            nonce:        nonces.geoOverrideSave,
            country_code: cgPendingChange.code,
            override:     cgPendingChange.newOverride,
        }, function(res) {
            if (res.success) {
                const country = cgGeoCountries.find(function(c) {
                    return c.code === cgPendingChange.code;
                });
                if (country) {
                    country.currentOverride  = cgPendingChange.newOverride;
                    country.effectivePenalty = cgGetEffectivePenalty(
                        country.basePenalty,
                        cgPendingChange.newOverride
                    );
                }

                cgRenderTierGroups(cgGeoCountries);
                cgUpdateSummary(cgGeoCountries);
                $('#cg-geo-impact').hide();
                cgPendingChange = null;

                const warnings = res.data.warnings || [];
                if (warnings.length > 0) {
                    $('#cg-geo-message')
                        .removeClass('error').addClass('success')
                        .html('✓ Saved. ⚠️ ' + escHtml(warnings[0].message))
                        .show();
                } else {
                    $('#cg-geo-message')
                        .removeClass('error').addClass('success')
                        .text('✓ Override saved successfully.')
                        .show();
                }
                setTimeout(function() { $('#cg-geo-message').fadeOut(); }, 4000);
            } else {
                $('#cg-geo-message')
                    .removeClass('success').addClass('error')
                    .text((res.data && res.data.message) || 'Failed to save. Try again.')
                    .show();
            }
            $btn.prop('disabled', false).text('✓ Apply Change');
        });
    });

    // Cancel
    $('#cg-geo-cancel').on('click', function() {
        cgPendingChange = null;
        $('#cg-geo-impact').hide();
    });

})(jQuery);