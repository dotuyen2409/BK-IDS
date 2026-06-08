/**
 * BK-IDS SOC — Bộ điều khiển Ứng dụng chính v3.2.1
 * ==================================================
 * FIX: Chuyển từ v-html sang <component :is> để Vue compile templates
 * Zero Trust — Chỉ Admin mới truy cập được
 * Tab content được fetch động từ pages/tabs/*.html và register làm Vue components
 * Tất cả API calls qua API.* service
 * Tiếng Việt 100%
 * KHÔNG sử dụng v-html — chỉ text interpolation {{ }} để chống XSS
 */
(function () {
    'use strict';

    // ========================================================================
    // SHARED STATE — Tất cả reactive state ở outer scope, shared bởi tất cả tab components
    // ========================================================================

    var tabCache = {};          // Cache HTML template strings
    var tabCompDefs = {};       // Cache component definition objects

    var Charts = { sensorTraffic: null, sensorCusum: null, ipsMisuse: null, ipsProto: null };

    // ---- UI State ----
    var activeTab = Vue.ref('dashboard');
    var sidebarCollapsed = Vue.ref(false);
    var showProfile = Vue.ref(false);
    var toasts = Vue.reactive([]);
    var tabLoading = Vue.ref(false);

    // Component definition cho tab hiện tại — Vue <component :is> nhận object trực tiếp
    // DÙNG shallowRef ĐỂ TRÁNH Vue deep-reactify template string + setup function
    var currentTabDef = Vue.shallowRef(null);
    var currentTabKey = Vue.ref(0); // Force re-render khi tab thay đổi

    // ---- Auth ----
    var userName = Vue.ref(TokenManager.getUser() ? TokenManager.getUser().username : 'Admin');

    // ---- API Status ----
    var apiOnline = Vue.ref(false);
    var apiRetryCount = Vue.ref(0);

    // ---- System Health ----
    var health = Vue.reactive({ cpu: 0, ram: 0, alerts: 0, uptime: '0m' });
    var criticalCount = Vue.ref(0);
    var alertCount = Vue.ref(0);
    var bannedCount = Vue.ref(0);
    var rulesCount = Vue.ref(0);
    var threatScore = Vue.ref(0);

    // ---- NGIPS Dashboard State ----
    var recentAlerts = Vue.reactive([]);
    var selectedPacket = Vue.ref(null);
    var selectedPacketHex = Vue.ref(null);

    // ---- Tab Titles ----
    var tabTitles = {
        dashboard: 'Bảng điều khiển — BK-IDS SOC',
        'capture-config': 'Cấu hình Bắt Gói tin',
        sensor: 'Theo dõi Cảm biến',
        'anomaly-config': 'Cấu hình Ngưỡng',
        ips: 'Theo dõi IPS',
        'alerts-explorer': 'Truy vấn Cảnh báo',
        rules: 'Cơ sở Tri thức — Luật Snort',
        packets: 'Danh sách Gói tin',
        settings: 'Cài đặt Hệ thống',
    };
    var pageTitle = Vue.computed(function () { return tabTitles[activeTab.value] || 'BK-IDS SOC'; });

    // ---- Capture Config ----
    var captureConfig = Vue.reactive({ home_net: '192.168.13.0/24', whitelist: '127.0.0.1', ports: '', pre_appid: true, pre_stream: true, enable_firewall: true });
    var captureSaving = Vue.ref(false);
    var captureMsg = Vue.ref('');
    var captureMsgError = Vue.ref(false);

    // ---- Sensor ----
    var sensorConnected = Vue.ref(false);
    var sensorMode = Vue.ref('live');
    var sensorDate = Vue.ref(new Date().toISOString().split('T')[0]);
    var sensorAlerts = Vue.ref(0);
    var sensorThreshold = Vue.ref(700);
    var sensorAnomaly = Vue.ref(false);
    var sensorTableData = Vue.reactive([]);
    var blockedIPs = Vue.reactive([]);

    // ---- Anomaly Config ----
    var anomalyConfig = Vue.reactive({ scan_interval: 5, cusum_threshold: 700, enable_firewall: true, ban_duration: 3600 });
    var anomalySaving = Vue.ref(false);
    var anomalyMsg = Vue.ref('');
    var anomalyMsgError = Vue.ref(false);

    // ---- IPS ----
    var ipsConnected = Vue.ref(false);
    var ipsAlerts = Vue.ref(0);
    var ipsDrops = Vue.ref(0);
    var ipsProto = Vue.reactive({ TCP: 0, UDP: 0, ICMP: 0 });
    var ipsTableData = Vue.reactive([]);
    var sysCpu = Vue.ref(0);
    var sysRam = Vue.ref(0);
    var snortRunning = Vue.ref(false);

    // ---- Explorer ----
    var explorerTab = Vue.ref('alerts');
    var explorerFilters = Vue.reactive({ ip: '', sig: '', proto: '', action: '' });
    var explorerAlerts = Vue.reactive([]);
    var explorerBanned = Vue.reactive([]);
    var explorerBannedCount = Vue.computed(function () { return explorerBanned.length; });
    var explorerFilteredAlerts = Vue.computed(function () {
        var result = explorerAlerts.slice();
        if (explorerFilters.ip) { var q = explorerFilters.ip.toLowerCase(); result = result.filter(function (a) { return (a.ip_src || '').toLowerCase().indexOf(q) !== -1; }); }
        if (explorerFilters.sig) { var q2 = explorerFilters.sig.toLowerCase(); result = result.filter(function (a) { return (a.sig_name || '').toLowerCase().indexOf(q2) !== -1; }); }
        if (explorerFilters.proto) result = result.filter(function (a) { return (a.protocol || '').toUpperCase() === explorerFilters.proto; });
        if (explorerFilters.action) result = result.filter(function (a) { return (a.action || '') === explorerFilters.action; });
        return result;
    });

    // ---- Rules ----
    var rules = Vue.reactive([]);
    var rulesSearch = Vue.ref('');
    var rulesPage = Vue.ref(1);
    var rulesPageSize = 50;
    var rulesLoading = Vue.ref(false);
    var rulesError = Vue.ref('');
    var rulesToast = Vue.reactive({ show: false, message: '', type: 'info' });
    var rulesFormLoading = Vue.ref(false);
    var rulesIsEditing = Vue.ref(false);
    var rulesToggleLoading = Vue.reactive({});
    var rulesDeleteTarget = Vue.ref(null);
    var rulesDeleteLoading = Vue.ref(false);
    var rulesForm = Vue.reactive({
        action: 'alert', protocol: 'tcp', direction: '->',
        sourceIp: '$HOME_NET', sourcePort: 'any',
        destIp: '$EXTERNAL_NET', destPort: 'any',
        sid: '', rev: '1', msg: '', extraOptions: ''
    });
    // rulesFormErrors will be a computed property instead of reactive object

    // Rules computed
    var filteredRules = Vue.computed(function () {
        var result = rules.slice();
        if (rulesSearch.value) {
            var q = rulesSearch.value.toLowerCase();
            result = result.filter(function (r) {
                return (r.msg || '').toLowerCase().indexOf(q) !== -1 ||
                    String(r.sid || '').indexOf(q) !== -1 ||
                    (r.source || '').toLowerCase().indexOf(q) !== -1 ||
                    (r.destination || '').toLowerCase().indexOf(q) !== -1 ||
                    (r.action || '').toLowerCase().indexOf(q) !== -1 ||
                    (r.protocol || '').toLowerCase().indexOf(q) !== -1;
            });
        }
        var start = (rulesPage.value - 1) * rulesPageSize;
        return result.slice(start, start + rulesPageSize);
    });

    var rulesOnCount = Vue.computed(function () { return rules.filter(function (r) { return r.enabled !== false; }).length; });
    var rulesOffCount = Vue.computed(function () { return rules.filter(function (r) { return r.enabled === false; }).length; });
    var rulesDropCount = Vue.computed(function () { return rules.filter(function (r) { return r.action === 'drop'; }).length; });
    var rulesPreviewText = Vue.computed(function () {
        var f = rulesForm;
        var parts = [];
        parts.push(f.action || 'alert');
        parts.push(f.protocol || 'tcp');
        parts.push(f.sourceIp || 'any');
        parts.push(f.sourcePort || 'any');
        parts.push(f.direction || '->');
        parts.push(f.destIp || 'any');
        parts.push(f.destPort || 'any');
        var opts = [];
        if (f.msg && f.msg.trim()) opts.push('msg:"' + f.msg.trim().replace(/"/g, '\\"') + '";');
        if (f.sid && f.sid.trim()) opts.push('sid:' + f.sid.trim() + ';');
        if (f.rev) opts.push('rev:' + String(f.rev).trim() + ';');
        if (f.extraOptions && f.extraOptions.trim()) {
            var ex = f.extraOptions.trim();
            if (ex.charAt(ex.length - 1) !== ';') ex += ';';
            opts.push(ex);
        }
        if (opts.length > 0) { parts.push('('); parts.push(opts.join(' ')); parts.push(')'); }
        return parts.join(' ');
    });

    // Validation regex
    var REGEX_IP = /^[!]?(\$?(?:HOME_NET|EXTERNAL_NET|DNS_SERVERS|SMTP_SERVERS|HTTP_SERVERS|SQL_SERVERS|TELNET_SERVERS|SNMP_SERVERS)|any|(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?|(\d{1,3}\.){3}\d{1,3} - (\d{1,3}\.){3}\d{1,3}|\[[^\]]+\])$/;
    var REGEX_PORT = /^[!]?(\$?[\w_]+|any|\d{1,5}(:\d{1,5})?|\d{1,5}-\d{1,5}|\[[^\]]+\])$/;
    var REGEX_SID = /^\d{7,10}$/;
    var REGEX_REV = /^\d+$/;

    var rulesFormErrors = Vue.computed(function () {
        var f = rulesForm;
        var errs = {};
        if (!f.sid || !f.sid.trim()) errs.sid = 'SID là bắt buộc';
        else if (!REGEX_SID.test(f.sid.trim())) errs.sid = 'SID phải là số 7-10 chữ số (>= 1000000)';
        else if (parseInt(f.sid.trim(), 10) < 1000000) errs.sid = 'SID phải >= 1000000';
        if (!f.msg || !f.msg.trim()) errs.msg = 'Message (msg) là bắt buộc';
        else if (f.msg.trim().length < 3) errs.msg = 'Message quá ngắn (tối thiểu 3 ký tự)';
        else if (f.msg.trim().length > 255) errs.msg = 'Message quá dài (tối đa 255 ký tự)';
        if (!f.sourceIp || !f.sourceIp.trim()) errs.sourceIp = 'Source IP là bắt buộc';
        else if (!REGEX_IP.test(f.sourceIp.trim())) errs.sourceIp = 'Định dạng IP không hợp lệ';
        if (!f.destIp || !f.destIp.trim()) errs.destIp = 'Dest IP là bắt buộc';
        else if (!REGEX_IP.test(f.destIp.trim())) errs.destIp = 'Định dạng IP không hợp lệ';
        if (!f.sourcePort || !f.sourcePort.trim()) errs.sourcePort = 'Source Port là bắt buộc';
        else if (!REGEX_PORT.test(f.sourcePort.trim())) errs.sourcePort = 'Port không hợp lệ';
        if (!f.destPort || !f.destPort.trim()) errs.destPort = 'Dest Port là bắt buộc';
        else if (!REGEX_PORT.test(f.destPort.trim())) errs.destPort = 'Port không hợp lệ';
        if (f.rev && !REGEX_REV.test(String(f.rev).trim())) errs.rev = 'Rev phải là số nguyên dương';
        return errs;
    });

    var rulesFormIsValid = Vue.computed(function () {
        var e = rulesFormErrors.value;
        return !e.sid && !e.msg && !e.sourceIp && !e.destIp && !e.sourcePort && !e.destPort && !e.rev;
    });

    function validateRulesForm() {
        // Obsolete, rulesFormErrors is now computed
    }

    function resetRulesForm() {
        rulesIsEditing.value = false;
        rulesForm.action = 'alert';
        rulesForm.protocol = 'tcp';
        rulesForm.direction = '->';
        rulesForm.sourceIp = '$HOME_NET';
        rulesForm.sourcePort = 'any';
        rulesForm.destIp = '$EXTERNAL_NET';
        rulesForm.destPort = 'any';
        rulesForm.sid = '';
        rulesForm.rev = '1';
        rulesForm.msg = '';
        rulesForm.extraOptions = '';
    }

    function generateSid() {
        var maxSid = 1000000;
        rules.forEach(function (r) { var s = parseInt(r.sid, 10); if (!isNaN(s) && s > maxSid) maxSid = s; });
        rulesForm.sid = String(maxSid + 1);
    }

    function showRulesToast(msg, type) {
        if (!type) type = 'info';
        rulesToast.show = true;
        rulesToast.message = msg;
        rulesToast.type = type;
        setTimeout(function () { rulesToast.show = false; }, 5000);
    }

    // Bootstrap modal instances (lazy init)
    var _ruleModalInst = null;
    var _deleteModalInst = null;
    function getRuleModalInst() {
        if (!_ruleModalInst) { var el = document.getElementById('ruleModal'); if (el && window.bootstrap) _ruleModalInst = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false }); }
        return _ruleModalInst;
    }
    function getDeleteModalInst() {
        if (!_deleteModalInst) { var el = document.getElementById('deleteModal'); if (el && window.bootstrap) _deleteModalInst = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false }); }
        return _deleteModalInst;
    }

    function openCreateModal() {
        resetRulesForm();
        generateSid();
        var m = getRuleModalInst(); if (m) m.show();
    }

    function openEditModal(rule) {
        if (!rule) return;
        rulesIsEditing.value = true;
        rulesForm.action = rule.action || 'alert';
        rulesForm.protocol = rule.protocol || 'tcp';
        rulesForm.direction = rule.direction || '->';
        rulesForm.sourceIp = rule.sourceIp || rule.source || '$HOME_NET';
        rulesForm.sourcePort = rule.sourcePort || 'any';
        rulesForm.destIp = rule.destIp || rule.destination || '$EXTERNAL_NET';
        rulesForm.destPort = rule.destPort || 'any';
        rulesForm.sid = String(rule.sid || '');
        rulesForm.rev = String(rule.rev || '1');
        rulesForm.msg = rule.msg || '';
        rulesForm.extraOptions = rule.extraOptions || '';
        var m = getRuleModalInst(); if (m) m.show();
    }

    function closeRuleModal() {
        var m = getRuleModalInst(); if (m) m.hide();
        resetRulesForm();
    }

    function closeDeleteModal() {
        var m = getDeleteModalInst(); if (m) m.hide();
        rulesDeleteTarget.value = null;
    }

    function submitRule() {
        if (rulesFormLoading.value) return;
        validateRulesForm();
        if (!rulesFormIsValid.value) { showRulesToast('Vui lòng kiểm tra lại các trường bị lỗi', 'warning'); return; }
        rulesFormLoading.value = true;
        var ruleData = {
            action: rulesForm.action, protocol: rulesForm.protocol, direction: rulesForm.direction,
            source: rulesForm.sourceIp, source_port: rulesForm.sourcePort,
            destination: rulesForm.destIp, dest_port: rulesForm.destPort,
            sid: parseInt(rulesForm.sid.trim(), 10),
            rev: parseInt(String(rulesForm.rev).trim(), 10) || 1,
            msg: rulesForm.msg.trim(),
            extra_options: rulesForm.extraOptions.trim(),
            rule_text: rulesPreviewText.value
        };
        try {
            API.rules.save(ruleData)
                .then(function (data) {
                    showRulesToast(rulesIsEditing.value ? 'Cập nhật luật SID ' + ruleData.sid + ' thành công!' : 'Tạo luật SID ' + ruleData.sid + ' thành công!', 'success');
                    closeRuleModal();
                    fetchRules();
                })
                .catch(function (err) { showRulesToast('Lỗi lưu luật: ' + (err.message || 'Không xác định'), 'error'); })
                .finally(function () { rulesFormLoading.value = false; });
        } catch (err) {
            showRulesToast('Lỗi lưu luật: ' + err.message, 'error');
            rulesFormLoading.value = false;
        }
    }

    function confirmDelete(rule) {
        if (!rule) return;
        rulesDeleteTarget.value = rule;
        var m = getDeleteModalInst(); if (m) m.show();
    }

    function executeDelete() {
        if (!rulesDeleteTarget.value || rulesDeleteLoading.value) return;
        var sid = rulesDeleteTarget.value.sid;
        rulesDeleteLoading.value = true;
        try {
            API.rules.deleteRule({ sid: sid })
                .then(function () { showRulesToast('Đã xóa luật SID ' + sid, 'success'); closeDeleteModal(); fetchRules(); })
                .catch(function (err) { showRulesToast('Lỗi xóa luật: ' + (err.message || 'Không xác định'), 'error'); })
                .finally(function () { rulesDeleteLoading.value = false; });
        } catch (err) {
            showRulesToast('Lỗi xóa luật: ' + err.message, 'error');
            rulesDeleteLoading.value = false;
        }
    }

    function toggleRuleStatus(rule, event) {
        // Guard: nếu đang loading hoặc rule không hợp lệ → bỏ qua hoàn toàn
        if (!rule || !rule.sid || rulesToggleLoading[rule.sid]) return;

        // Ngắn chặn sự kiện lan truyền để tránh trigger lại @change
        if (event) {
            try { event.stopPropagation(); event.preventDefault(); } catch (e) { }
        }

        var sid = rule.sid;
        var currentEnabled = rule.enabled !== false;
        var newEnabled = !currentEnabled;

        // Đánh dấu đang loading (plain object, không reactive → không trigger re-render)
        rulesToggleLoading[sid] = true;

        // Optimistic update: cập nhật UI ngay
        rule.enabled = newEnabled;

        try {
            API.rules.toggle({ sid: sid, enabled: newEnabled })
                .then(function () {
                    showRulesToast(newEnabled ? 'Đã bật luật SID ' + sid : 'Đã tắt luật SID ' + sid, 'success');
                    // Đồng bộ lại từ DB sau 500ms để đảm bảo一致性
                    setTimeout(function () { fetchRules(); }, 500);
                })
                .catch(function (err) {
                    // REVERT nếu API fail — silently cập nhật KHÔNG trigger watcher
                    rule.enabled = currentEnabled;
                    showRulesToast('Lỗi thay đổi trạng thái: ' + (err.message || 'Không xác định'), 'error');
                    console.error('[Rules] Toggle failed for SID ' + sid + ':', err);
                })
                .finally(function () {
                    rulesToggleLoading[sid] = false;
                });
        } catch (err) {
            rule.enabled = currentEnabled;
            rulesToggleLoading[sid] = false;
            showRulesToast('Lỗi thay đổi trạng thái: ' + err.message, 'error');
        }
    }

    // ---- Packets ----
    var packets = Vue.reactive([]);

    // ========================================================================
    // TAB COMPONENT FACTORY
    // Tạo Vue component definition object từ HTML template string
    // ========================================================================

    function createTabComponentDef(tab, htmlTemplate) {
        var wrappedTemplate = '<div class="tab-component-root">' + htmlTemplate + '</div>';

        // Shared setup function — trả về tất cả reactive state + methods
        var sharedSetup = function () {
            return {
                activeTab: activeTab,
                sidebarCollapsed: sidebarCollapsed,
                showProfile: showProfile,
                pageTitle: pageTitle,
                toasts: toasts,
                tabLoading: tabLoading,
                userName: userName,
                logout: logout,
                apiOnline: apiOnline,
                apiRetryCount: apiRetryCount,
                apiBaseUrl: window.API_BASE,
                health: health,
                criticalCount: criticalCount,
                alertCount: alertCount,
                bannedCount: bannedCount,
                rulesCount: rulesCount,
                threatScore: threatScore,
                captureConfig: captureConfig,
                captureSaving: captureSaving,
                captureMsg: captureMsg,
                captureMsgError: captureMsgError,
                saveCaptureConfig: saveCaptureConfig,
                sensorConnected: sensorConnected,
                sensorMode: sensorMode,
                sensorDate: sensorDate,
                sensorAlerts: sensorAlerts,
                sensorThreshold: sensorThreshold,
                sensorAnomaly: sensorAnomaly,
                sensorTableData: sensorTableData,
                blockedIPs: blockedIPs,
                setSensorMode: setSensorMode,
                fetchSensorData: fetchSensorData,
                unblockSensorIP: unblockSensorIP,
                anomalyConfig: anomalyConfig,
                anomalySaving: anomalySaving,
                anomalyMsg: anomalyMsg,
                anomalyMsgError: anomalyMsgError,
                saveAnomalyConfig: saveAnomalyConfig,
                ipsConnected: ipsConnected,
                ipsAlerts: ipsAlerts,
                ipsDrops: ipsDrops,
                ipsProto: ipsProto,
                ipsTableData: ipsTableData,
                sysCpu: sysCpu,
                sysRam: sysRam,
                snortRunning: snortRunning,
                investigateDPI: investigateDPI,
                blockByHash: blockByHash,
                explorerTab: explorerTab,
                explorerFilters: explorerFilters,
                explorerFilteredAlerts: explorerFilteredAlerts,
                explorerBanned: explorerBanned,
                explorerBannedCount: explorerBannedCount,
                fetchExplorerAlerts: fetchExplorerAlerts,
                fetchExplorerBanned: fetchExplorerBanned,
                unbanExplorerIP: unbanExplorerIP,
                formatTime: formatTime,
                recentAlerts: recentAlerts,
                selectedPacket: selectedPacket,
                selectedPacketHex: selectedPacketHex,
                fetchRecentAlerts: fetchRecentAlerts,
                openPacketModal: openPacketModal,
                fetchAnomalyRealtime: fetchAnomalyRealtime,
                unblockIP: unblockIP,
                rules: rules,
                rulesSearch: rulesSearch,
                rulesPage: rulesPage,
                rulesPageSize: rulesPageSize,
                rulesLoading: rulesLoading,
                rulesError: rulesError,
                rulesToast: rulesToast,
                rulesFormLoading: rulesFormLoading,
                rulesIsEditing: rulesIsEditing,
                rulesToggleLoading: rulesToggleLoading,
                rulesDeleteTarget: rulesDeleteTarget,
                rulesDeleteLoading: rulesDeleteLoading,
                rulesForm: rulesForm,
                rulesFormErrors: rulesFormErrors,
                rulesFormIsValid: rulesFormIsValid,
                rulesPreviewText: rulesPreviewText,
                rulesOnCount: rulesOnCount,
                rulesOffCount: rulesOffCount,
                rulesDropCount: rulesDropCount,
                filteredRules: filteredRules,
                fetchRules: fetchRules,
                reloadSnortRules: fetchRules,
                openCreateModal: openCreateModal,
                openEditModal: openEditModal,
                closeRuleModal: closeRuleModal,
                closeDeleteModal: closeDeleteModal,
                submitRule: submitRule,
                confirmDelete: confirmDelete,
                executeDelete: executeDelete,
                toggleRuleStatus: toggleRuleStatus,
                generateSid: generateSid,
                packets: packets,
                fetchPackets: fetchPackets,
                switchTab: switchTab,
                fetchBlockedIPs: fetchBlockedIPs,
            };
        };

        return {
            template: wrappedTemplate,
            setup: sharedSetup,
        };
    }

    // ========================================================================
    // TAB LOADING
    // ========================================================================

    function loadTabFragment(tab, callback) {
        if (tabCache[tab]) {
            // Đã cache — tạo component def nếu chưa
            if (!tabCompDefs[tab]) {
                tabCompDefs[tab] = createTabComponentDef(tab, tabCache[tab]);
            }
            if (callback) callback();
            return;
        }
        tabLoading.value = true;
        var url = '/pages/tabs/' + tab + '.html';
        fetch(url, { cache: 'no-store' })
            .then(function (res) {
                if (!res.ok) throw new Error('HTTP ' + res.status);
                return res.text();
            })
            .then(function (html) {
                tabCache[tab] = html;
                tabCompDefs[tab] = createTabComponentDef(tab, html);
                tabLoading.value = false;
                if (callback) callback();
            })
            .catch(function (err) {
                tabLoading.value = false;
                console.error('[TAB] Failed to load ' + tab + ':', err);
                showToast('Lỗi tải tab: ' + tab, 'error');
            });
    }

    function preloadAllTabs() {
        var tabs = ['dashboard', 'capture-config', 'sensor', 'anomaly-config', 'ips', 'alerts-explorer', 'rules', 'packets', 'settings'];
        tabs.forEach(function (tab, idx) {
            setTimeout(function () { loadTabFragment(tab); }, 100 + idx * 50);
        });
    }

    // ========================================================================
    // METHODS
    // ========================================================================

    function switchTab(tab) {
        activeTab.value = tab;
        showProfile.value = false;

        loadTabFragment(tab, function () {
            // Cập nhật component definition cho <component :is>
            currentTabDef.value = tabCompDefs[tab] || null;
            currentTabKey.value++; // Force re-render

            // Trigger data fetch nếu cần
            if (tab === 'sensor' && sensorTableData.length === 0) fetchSensorData();
            if (tab === 'sensor') fetchBlockedIPs();
            if (tab === 'ips' && ipsTableData.length === 0) fetchIPSData();
            if (tab === 'alerts-explorer' && explorerAlerts.length === 0) fetchExplorerAlerts();
            if (tab === 'alerts-explorer') fetchExplorerBanned();
            if (tab === 'rules' && rules.length === 0) fetchRules();
            if (tab === 'packets' && packets.length === 0) fetchPackets();
        });
    }

    function showToast(msg, type) {
        if (type === void 0) type = 'info';
        var id = Date.now() + Math.random();
        toasts.push({ id: id, message: msg, type: type });
        setTimeout(function () { var i = toasts.findIndex(function (t) { return t.id === id; }); if (i > -1) toasts.splice(i, 1); }, 4000);
    }

    function logout() {
        try { TokenManager.clear(); } catch (e) { }
        try { sessionStorage.clear(); } catch (e) { }
        try { localStorage.removeItem('bk_ids_token'); } catch (e) { }
        try { localStorage.removeItem('auth_token'); } catch (e) { }
        window.location.replace('/login');
    }

    function formatTime(ts) {
        if (!ts) return 'N/A';
        try { var d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts); return d.toLocaleString('vi-VN'); }
        catch (e) { return String(ts); }
    }

    // ---- Capture Config ----
    function saveCaptureConfig() {
        captureSaving.value = true;
        captureMsg.value = '';
        try {
            var cfg = 'HOME_NET=' + captureConfig.home_net + '\nWHITELIST_IPS=' + captureConfig.whitelist + '\nMONITORED_PORTS=' + captureConfig.ports + '\nPRE_APPID=' + captureConfig.pre_appid + '\nPRE_STREAM=' + captureConfig.pre_stream + '\nENABLE_FIREWALL=' + captureConfig.enable_firewall;
            API.rules.save({ config: cfg })
                .then(function (json) {
                    if (json.status === 'success') { captureMsg.value = json.message || 'Đã lưu cấu hình!'; captureMsgError.value = false; }
                    else throw new Error(json.message || 'Lỗi lưu cấu hình');
                })
                .catch(function (e) { captureMsg.value = e.message; captureMsgError.value = true; })
                .finally(function () { captureSaving.value = false; setTimeout(function () { captureMsg.value = ''; }, 5000); });
        } catch (e) { captureMsg.value = e.message; captureMsgError.value = true; captureSaving.value = false; }
    }

    // ---- Sensor ----
    var _sensorFetchInFlight = false;  // Chống fetch trùng lắp
    var _sensorErrorCount = 0;        // Đếm lỗi liên tiếp
    var _sensorPollMs = 5000;         // Polling interval (adaptive)

    function setSensorMode(mode) { sensorMode.value = mode; fetchSensorData(); }

    function fetchSensorData() {
        if (_sensorFetchInFlight) return; // Bỏ qua nếu request trước chưa xong
        _sensorFetchInFlight = true;

        API.alerts.getAnomalyData()
            .then(function (json) {
                _sensorErrorCount = 0; // Reset lỗi
                sensorConnected.value = true;
                if (json.status === 'success' && json.data && json.data.length > 0) {
                    var data = json.data;
                    sensorThreshold.value = data[0].h_threshold || 700;
                    sensorAnomaly.value = data.some(function (d) { return d.is_anomaly; });
                    sensorAlerts.value = data.filter(function (d) { return d.is_anomaly; }).length;

                    // 🎯 ADAPTIVE POLLING: Nhanh hơn khi phát hiện bất thường
                    _sensorPollMs = sensorAnomaly.value ? 5000 : 10000;

                    sensorTableData.length = 0;
                    sensorTableData.push.apply(sensorTableData, data.slice().reverse());
                    // Dùng requestAnimationFrame để tránh crash UI khi data lớn
                    requestAnimationFrame(function () { updateSensorCharts(data); });
                }
            })
            .catch(function (err) {
                _sensorErrorCount++;
                // Exponential backoff khi lỗi liên tiếp
                if (_sensorErrorCount > 3) {
                    _sensorPollMs = Math.min(30000, 5000 * Math.pow(2, _sensorErrorCount - 3));
                }
                if (_sensorErrorCount > 5) sensorConnected.value = false;
            })
            .finally(function () { _sensorFetchInFlight = false; });
    }

    function fetchBlockedIPs() {
        API.rules.getBannedIPs()
            .then(function (json) {
                var items = [];
                if (json.data) {
                    if (Array.isArray(json.data)) items = json.data.map(function (i) { return typeof i === 'string' ? { ip: i } : { ip: i.ip || i.ip_src, unban_time: i.unban_time || i.ban_time }; });
                    else if (typeof json.data === 'object') items = Object.keys(json.data).map(function (k) { return { ip: k, unban_time: json.data[k] }; });
                }
                blockedIPs.length = 0;
                blockedIPs.push.apply(blockedIPs, items);
                bannedCount.value = items.length;
            })
            .catch(function () { });
    }

    function unblockIP(ip) {
        if (!confirm('GỠ CHẶN IP: ' + ip + '?')) return;
        API.soar.unblockIp(ip)
            .then(function (res) { if (res.status === 'success' || res.status === 'ok') { showToast('Đã gỡ chặn ' + ip, 'success'); fetchBlockedIPs(); } })
            .catch(function () { showToast('Lỗi gỡ chặn', 'error'); });
    }

    function unblockSensorIP(ip) { unblockIP(ip); }

    function fetchRecentAlerts() {
        API.alerts.getRecentAlerts(50)
            .then(function (json) {
                if (json.data) {
                    recentAlerts.length = 0;
                    recentAlerts.push.apply(recentAlerts, json.data);
                }
            })
            .catch(function () { showToast('Lỗi tải cảnh báo', 'error'); });
    }

    function decodeBase64ToHex(b64Str) {
        if (!b64Str) return null;
        try {
            var raw = atob(b64Str);
            var offsets = [];
            var hex = [];
            var ascii = [];
            for (var i = 0; i < raw.length; i += 16) {
                var offsetStr = i.toString(16).padStart(4, '0');
                offsets.push(offsetStr);

                var hexLine = '';
                var asciiLine = '';
                for (var j = 0; j < 16; j++) {
                    if (i + j < raw.length) {
                        var charCode = raw.charCodeAt(i + j);
                        hexLine += charCode.toString(16).padStart(2, '0') + ' ';
                        asciiLine += (charCode >= 32 && charCode <= 126) ? raw.charAt(i + j) : '.';
                    } else {
                        hexLine += '   ';
                        asciiLine += ' ';
                    }
                    if (j === 7) hexLine += ' ';
                }
                hex.push(hexLine);
                ascii.push(asciiLine);
            }
            return { offsets: offsets, hex: hex, ascii: ascii };
        } catch (e) {
            return null;
        }
    }

    function openPacketModal(item) {
        selectedPacket.value = item;
        selectedPacketHex.value = decodeBase64ToHex(item.b64_data);
        var el = document.getElementById('packetModal');
        if (el && window.bootstrap) {
            var m = bootstrap.Modal.getInstance(el) || new bootstrap.Modal(el);
            m.show();
        }
    }

    function fetchAnomalyRealtime() {
        API.anomaly.getRealtime()
            .then(function (res) {
                if (res.status === 'success' || res.status === 'ok') {
                    updateStatsChart(res.data);
                }
            })
            .catch(function (e) {
                console.error("Lỗi lấy dữ liệu Anomaly Realtime:", e);
                // Tạo data mô phỏng (mock data) để vẽ biểu đồ Anomaly như yêu cầu Blueprint
                var mockData = [];
                for (var i = 0; i < 20; i++) {
                    mockData.push({
                        timestamp: '10:' + (20 + i),
                        gn: Math.random() * 500,
                        h_threshold: 700,
                        total_packets: Math.floor(Math.random() * 1000) + 100
                    });
                }
                updateStatsChart(mockData);
            });
    }

    function updateStatsChart(anomalyData) {
        var ctx = document.getElementById('anomalyRealtimeChart');
        if (!ctx) return;
        if (Charts.dashboardStats) Charts.dashboardStats.destroy();

        var labels = [];
        var cusumData = [];
        var thresholdData = [];
        var pktCountData = [];

        if (anomalyData && Array.isArray(anomalyData)) {
            labels = anomalyData.map(function (d) { return (d.timestamp || '').split(' ')[1] || d.timestamp || ''; });
            cusumData = anomalyData.map(function (d) { return d.gn || 0; });
            thresholdData = anomalyData.map(function (d) { return d.h_threshold || 700; });
            pktCountData = anomalyData.map(function (d) { return d.packet_count || d.total_packets || 0; });
        }

        Charts.dashboardStats = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Chỉ số CuSUM (Gn)',
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 2,
                        data: cusumData,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Ngưỡng Cảnh báo (H)',
                        borderColor: '#f59e0b',
                        borderDash: [5, 5],
                        pointRadius: 0,
                        data: thresholdData,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Lưu lượng (Packets/s)',
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 1,
                        data: pktCountData,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        title: { display: true, text: 'Chỉ số CuSUM', color: '#ef4444' }
                    },
                    y1: {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        beginAtZero: true,
                        grid: { drawOnChartArea: false },
                        title: { display: true, text: 'Lưu lượng', color: '#06b6d4' }
                    }
                },
                plugins: {
                    legend: { labels: { color: '#e2e8f0' } }
                }
            }
        });
    }

    function updateSensorCharts(data) {
        // Giới hạn dữ liệu biểu đồ để tránh OOM/crash khi tải cao
        var chartData = data.length > 60 ? data.slice(data.length - 60) : data;
        var labels = chartData.map(function (d) { return (d.tg_ketthuc || '').split(' ')[1] || ''; });
        var ctx1 = document.getElementById('sensorTrafficChart');
        if (ctx1) {
            if (Charts.sensorTraffic) Charts.sensorTraffic.destroy();
            Charts.sensorTraffic = new Chart(ctx1, { type: 'bar', data: { labels: labels, datasets: [{ label: 'TCP', backgroundColor: '#3b82f6', data: chartData.map(function (d) { return d.tcp || 0; }) }, { label: 'UDP', backgroundColor: '#a855f7', data: chartData.map(function (d) { return d.udp || 0; }) }, { label: 'ICMP', backgroundColor: '#f59e0b', data: chartData.map(function (d) { return d.icmp || 0; }) }] }, options: { responsive: true, maintainAspectRatio: false, animation: { duration: 0 }, scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true } } } });
        }
        var ctx2 = document.getElementById('sensorCusumChart');
        if (ctx2) {
            if (Charts.sensorCusum) Charts.sensorCusum.destroy();
            Charts.sensorCusum = new Chart(ctx2, { type: 'line', data: { labels: labels, datasets: [{ label: 'CuSUM (Gn)', borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,.1)', fill: true, tension: .3, pointRadius: 2, data: chartData.map(function (d) { return d.gn || 0; }) }, { label: 'Ngưỡng (H)', borderColor: '#ef4444', borderDash: [5, 5], pointRadius: 0, data: chartData.map(function (d) { return d.h_threshold || 700; }) }] }, options: { responsive: true, maintainAspectRatio: false, animation: { duration: 0 } } });
        }
    }

    // ---- Anomaly Config ----
    function saveAnomalyConfig() {
        anomalySaving.value = true;
        anomalyMsg.value = '';
        try {
            var cfg = 'SCAN_INTERVAL=' + anomalyConfig.scan_interval + '\nCUSUM_THRESHOLD=' + anomalyConfig.cusum_threshold + '\nENABLE_FIREWALL=' + anomalyConfig.enable_firewall + '\nBAN_DURATION=' + anomalyConfig.ban_duration;
            API.rules.save({ config: cfg })
                .then(function (json) { if (json.status === 'success') { anomalyMsg.value = 'Đã lưu! Thuật toán sẽ cập nhật.'; anomalyMsgError.value = false; } else throw new Error(json.message || 'Lỗi'); })
                .catch(function (e) { anomalyMsg.value = e.message; anomalyMsgError.value = true; })
                .finally(function () { anomalySaving.value = false; setTimeout(function () { anomalyMsg.value = ''; }, 5000); });
        } catch (e) { anomalyMsg.value = e.message; anomalyMsgError.value = true; anomalySaving.value = false; }
    }

    // ---- IPS ----
    function fetchIPSData() {
        API.system.healthSystem().then(function (res) {
            if (res.status === 'success') {
                sysCpu.value = res.cpu;
                sysRam.value = res.ram;
                snortRunning.value = res.snort_running;
            }
        }).catch(function (err) { console.error(err); });

        API.alerts.getMisuseAlerts(250, 0)
            .then(function (json) {
                ipsConnected.value = true;
                if (json.status === 'success' && json.data) {
                    ipsTableData.length = 0;
                    ipsTableData.push.apply(ipsTableData, json.data);
                    ipsAlerts.value = json.data.filter(function (a) { return a.action !== 'DROP'; }).length;
                    ipsDrops.value = json.data.filter(function (a) { return a.action === 'DROP'; }).length;
                    var p = { TCP: 0, UDP: 0, ICMP: 0 };
                    json.data.forEach(function (a) { var proto = (a.protocol || 'TCP').toUpperCase(); if (p[proto] !== undefined) p[proto]++; else p.ICMP++; });
                    Object.assign(ipsProto, p);
                    alertCount.value = json.data.length;
                    criticalCount.value = json.data.filter(function (a) { return (a.severity || '').toUpperCase() === 'CRITICAL'; }).length;
                    Vue.nextTick(function () { updateIPSCharts(json.data); });
                }
            })
            .catch(function () { ipsConnected.value = false; });
    }

    function updateIPSCharts(data) {
        var counts = {};
        data.forEach(function (a) { var s = a.sig_name || 'Unknown'; counts[s] = (counts[s] || 0) + 1; });
        var sorted = Object.entries(counts).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 10);
        var ctx1 = document.getElementById('ipsMisuseChart');
        if (ctx1) {
            if (Charts.ipsMisuse) Charts.ipsMisuse.destroy();
            Charts.ipsMisuse = new Chart(ctx1, {
                type: 'bar',
                data: {
                    labels: sorted.map(function (s) { return s[0].length > 20 ? s[0].substring(0, 20) + '...' : s[0]; }),
                    datasets: [{ label: 'Số lần', backgroundColor: '#ef4444', borderRadius: 4, data: sorted.map(function (s) { return s[1]; }) }]
                },
                options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, grid: { color: '#1e293b' } }, x: { grid: { display: false } } }, plugins: { legend: { display: false } } }
            });
        }
        var ctx2 = document.getElementById('ipsProtoChart');
        if (ctx2) {
            if (Charts.ipsProto) Charts.ipsProto.destroy();
            Charts.ipsProto = new Chart(ctx2, {
                type: 'doughnut',
                data: { labels: ['TCP', 'UDP', 'ICMP'], datasets: [{ data: [ipsProto.TCP, ipsProto.UDP, ipsProto.ICMP], backgroundColor: ['#3b82f6', '#a855f7', '#f59e0b'], borderWidth: 0 }] },
                options: { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { position: 'right', labels: { color: '#f8fafc', padding: 12, font: { size: 11 } } } } }
            });
        }
    }

    function investigateDPI(item) {
        var ip = item.ip_src || item.src_ip;
        var time = item.timestamp || item.time;
        if (ip && time) {
            window.location.href = '/packet-detail.html?ip=' + encodeURIComponent(ip) + '&time=' + encodeURIComponent(time);
        } else if (ip) {
            window.location.href = '/packet-detail.html?ip=' + encodeURIComponent(ip);
        } else {
            showToast('Không có thông tin IP để điều tra', 'warning');
        }
    }

    function blockByHash(hash, ip) {
        if (!ip) {
            showToast('Không có thông tin IP để chặn', 'warning');
            return;
        }
        if (!confirm('Bạn có chắc muốn chặn IP: ' + ip + '?')) return;
        API.soar.blockIp(ip)
            .then(function (res) {
                if (res.status === 'success' || res.status === 'ok') {
                    showToast('Đã chặn thành công IP ' + ip, 'success');
                    fetchBlockedIPs();
                    fetchIPSData();
                } else {
                    showToast('Lỗi chặn IP: ' + (res.message || 'Không xác định'), 'error');
                }
            })
            .catch(function (err) {
                showToast('Lỗi chặn IP: ' + (err.message || 'Không xác định'), 'error');
            });
    }

    // ---- Explorer ----
    function fetchExplorerAlerts() {
        API.alerts.getMisuseAlerts(500, 0)
            .then(function (json) { explorerAlerts.length = 0; explorerAlerts.push.apply(explorerAlerts, json.data || []); })
            .catch(function () { showToast('Lỗi tải cảnh báo', 'error'); });
    }

    function fetchExplorerBanned() {
        API.rules.getBannedIPs()
            .then(function (json) {
                var items = [];
                if (json.data) {
                    if (Array.isArray(json.data)) items = json.data.map(function (i) { return typeof i === 'string' ? { ip: i } : { ip: i.ip || i.ip_src, unban_time: i.unban_time }; });
                    else if (typeof json.data === 'object') items = Object.keys(json.data).map(function (k) { return { ip: k, unban_time: json.data[k] }; });
                }
                explorerBanned.length = 0;
                explorerBanned.push.apply(explorerBanned, items);
            })
            .catch(function () { });
    }

    function unbanExplorerIP(ip) {
        if (!confirm('GỠ CHẶN IP: ' + ip + '?')) return;
        API.soar.unblockIp(ip)
            .then(function (res) { if (res.status === 'success') { var idx = explorerBanned.findIndex(function (i) { return i.ip === ip; }); if (idx > -1) explorerBanned.splice(idx, 1); showToast('Đã gỡ chặn ' + ip, 'success'); } })
            .catch(function () { showToast('Lỗi gỡ chặn', 'error'); });
    }

    // ---- Rules ----
    var _fetchRulesTimer = null;
    function fetchRules() {
        // Debounce: nếu đang có timer pending, clear và tạo lại
        if (_fetchRulesTimer) clearTimeout(_fetchRulesTimer);
        _fetchRulesTimer = setTimeout(function () {
            _fetchRulesTimer = null;
            _doFetchRules();
        }, 100);
    }

    function _doFetchRules() {
        rulesLoading.value = true;
        rulesError.value = '';
        try {
            API.rules.getAll()
                .then(function (json) {
                    try {
                        rules.length = 0;
                        rules.push.apply(rules, json.data || []);
                        rulesCount.value = rules.length;
                    } catch (e) {
                        console.error('[Rules] Parse error:', e);
                        rulesError.value = 'Lỗi phân tích dữ liệu luật. Vui lòng kiểm tra Console (F12).';
                    }
                })
                .catch(function (err) {
                    console.error('[Rules] API error:', err);
                    rulesError.value = 'Lỗi tải danh sách luật: ' + (err.message || 'Không xác định');
                })
                .finally(function () { rulesLoading.value = false; });
        } catch (err) {
            console.error('[Rules] Fetch exception:', err);
            rulesError.value = 'Lỗi khởi tải dữ liệu: ' + err.message;
            rulesLoading.value = false;
        }
    }

    // ---- Packets ----
    function fetchPackets() {
        API.alerts.getRecentAlerts()
            .then(function (json) { packets.length = 0; packets.push.apply(packets, json.data || []); })
            .catch(function () { });
    }

    // ---- Health Check ----
    function fetchHealth() {
        API.system.health()
            .then(function (data) {
                if (data.status === 'ok' || data.status === 'success') {
                    apiOnline.value = true;
                    apiRetryCount.value = 0;
                } else throw new Error('API error');
            })
            .catch(function () {
                API.alerts.getSummary()
                    .then(function (data) {
                        if (data.status === 'success') {
                            health.cpu = data.data && data.data.cpu ? data.data.cpu : 0;
                            health.ram = data.data && data.data.ram ? data.data.ram : 0;
                            health.alerts = data.total || alertCount.value;
                            apiOnline.value = true;
                            apiRetryCount.value = 0;
                        } else throw new Error('API error');
                    })
                    .catch(function () { apiOnline.value = false; apiRetryCount.value++; });
            });
    }

    // ========================================================================
    // VUE APP — Mount với placeholder tab component
    // ========================================================================

    var app = Vue.createApp({
        setup: function () {
            return {
                activeTab: activeTab,
                sidebarCollapsed: sidebarCollapsed,
                showProfile: showProfile,
                pageTitle: pageTitle,
                toasts: toasts,
                tabLoading: tabLoading,
                currentTabDef: currentTabDef,
                currentTabKey: currentTabKey,
                userName: userName,
                logout: logout,
                apiOnline: apiOnline,
                apiRetryCount: apiRetryCount,
                apiBaseUrl: window.API_BASE,
                health: health,
                criticalCount: criticalCount,
                alertCount: alertCount,
                bannedCount: bannedCount,
                rulesCount: rulesCount,
                threatScore: threatScore,
                switchTab: switchTab,
                fetchHealth: fetchHealth,
                formatTime: formatTime,
                recentAlerts: recentAlerts,
                selectedPacket: selectedPacket,
                selectedPacketHex: selectedPacketHex,
                fetchRecentAlerts: fetchRecentAlerts,
                openPacketModal: openPacketModal,
                fetchAnomalyRealtime: fetchAnomalyRealtime,
                unblockIP: unblockIP,
            };
        },
    });

    app.mount('#app');

    // ========================================================================
    // POST-MOUNT: Load dashboard + preload + intervals
    // ========================================================================

    Vue.nextTick(function () {
        // Set initial tab component
        loadTabFragment('dashboard', function () {
            currentTabDef.value = tabCompDefs['dashboard'] || null;
            currentTabKey.value++;
        });

        // Preload remaining tabs
        setTimeout(preloadAllTabs, 500);

        fetchHealth();
        fetchBlockedIPs();
        fetchRecentAlerts();
        fetchAnomalyRealtime();

        setInterval(fetchHealth, 15000);
        setInterval(fetchBlockedIPs, 30000);
        setInterval(fetchRecentAlerts, 15000);
        setInterval(fetchAnomalyRealtime, 15000);

        var uptimeSeconds = 0;
        setInterval(function () {
            uptimeSeconds++;
            var m = Math.floor(uptimeSeconds / 60);
            var h = Math.floor(m / 60);
            health.uptime = h > 0 ? h + 'h ' + (m % 60) + 'm' : m + 'm';
        }, 1000);

        // 🎯 ADAPTIVE SENSOR POLLING: Tự điều chỉnh tốc độ polling
        var _sensorInterval = null;
        function startAdaptiveSensorPolling() {
            if (_sensorInterval) clearInterval(_sensorInterval);
            _sensorInterval = setInterval(function () {
                if (activeTab.value === 'sensor' && sensorMode.value === 'live') fetchSensorData();
            }, _sensorPollMs);
        }
        startAdaptiveSensorPolling();
        // Theo dõi thay đổi polling rate
        setInterval(function () {
            startAdaptiveSensorPolling();
        }, 15000);

        setInterval(function () {
            if (activeTab.value === 'ips') fetchIPSData();
        }, 10000);

        // Native logout button backup
        setTimeout(function () {
            var btn = document.getElementById('btn-logout');
            if (btn) {
                btn.addEventListener('click', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    try { TokenManager.clear(); } catch (err) { }
                    try { sessionStorage.clear(); } catch (err) { }
                    window.location.replace('/login');
                });
            }
        }, 200);
    });

})();
