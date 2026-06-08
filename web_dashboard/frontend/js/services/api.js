/**
 * BK-IDS SOC — API Service Layer v3.2 (Zero Trust)
 * ==================================================
 * BASE_URL: dynamic từ window.location.hostname
 * Auto-retry với backoff, JWT refresh, timeout per-request
 * Mọi request đều qua hàm request() — không fetch trực tiếp
 */
(function() {
    'use strict';

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    const API_BASE = (() => {
        if (window.__BK_API_BASE__) return window.__BK_API_BASE__;
        const host = window.location.hostname;
        const port = window.location.port;
        const path = window.location.pathname;
        if (port === '9000' || path.startsWith('/soc-admin')) return '/soc-api';
        if (port === '5050') return 'http://' + host + ':5050/api';
        return '/api';
    })();

    const REQUEST_TIMEOUT    = 15000;
    const RETRY_MAX_ATTEMPTS = 2;
    const RETRY_BASE_DELAY   = 3000;
    const TOKEN_REFRESH_BUFFER = 60000;

    // ========================================================================
    // TOKEN MANAGEMENT
    // ========================================================================

    const TokenManager = {
        getAccessToken() {
            // Primary: sessionStorage
            var t = sessionStorage.getItem('bk_ids_token');
            if (t) return t;
            // Fallback: localStorage
            t = localStorage.getItem('bk_ids_token');
            if (t) {
                // Sync back to sessionStorage
                sessionStorage.setItem('bk_ids_token', t);
                return t;
            }
            // Last resort: other common keys
            t = localStorage.getItem('jwt_token') || localStorage.getItem('auth_token') || localStorage.getItem('token');
            if (t) {
                sessionStorage.setItem('bk_ids_token', t);
                return t;
            }
            return null;
        },
        getRefreshToken() {
            var t = sessionStorage.getItem('bk_ids_refresh_token');
            if (t) return t;
            t = localStorage.getItem('bk_ids_refresh_token');
            if (t) {
                sessionStorage.setItem('bk_ids_refresh_token', t);
                return t;
            }
            return null;
        },

        setTokens(accessToken, refreshToken) {
            sessionStorage.setItem('bk_ids_token', accessToken);
            if (refreshToken) sessionStorage.setItem('bk_ids_refresh_token', refreshToken);
        },

        setUser(user) { sessionStorage.setItem('bk_ids_user', JSON.stringify(user)); },

        getUser() {
            try { return JSON.parse(sessionStorage.getItem('bk_ids_user') || 'null'); }
            catch { return null; }
        },

        isAuthenticated() {
            const token = this.getAccessToken();
            if (!token) return false;
            const parts = token.split('.');
            if (parts.length !== 3) return false;
            try {
                const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
                if (payload.exp && (payload.exp * 1000) < Date.now()) return false;
            } catch { return false; }
            return true;
        },

        isAdmin() {
            const user = this.getUser();
            return user && user.role === 'admin';
        },

        clear() {
            sessionStorage.removeItem('bk_ids_token');
            sessionStorage.removeItem('bk_ids_refresh_token');
            sessionStorage.removeItem('bk_ids_user');
        },

        decodePayload(token) {
            try {
                const parts = token.split('.');
                if (parts.length !== 3) return null;
                return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            } catch { return null; }
        },

        needsRefresh() {
            const token = this.getAccessToken();
            if (!token) return false;
            const payload = this.decodePayload(token);
            if (!payload || !payload.exp) return true;
            return (payload.exp * 1000) < (Date.now() + TOKEN_REFRESH_BUFFER);
        }
    };

    // ========================================================================
    // HTTP CLIENT
    // ========================================================================

    function buildHeaders(extra) {
        const h = { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
        if (extra) Object.assign(h, extra);
        const token = TokenManager.getAccessToken();
        if (token) h['Authorization'] = 'Bearer ' + token;
        return h;
    }

    function sleep(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }

    async function tryRefreshToken() {
        const rt = TokenManager.getRefreshToken();
        if (!rt) return false;
        try {
            const res = await fetch(API_BASE + '/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: rt }),
            });
            if (!res.ok) return false;
            const data = await res.json();
            if (data.status === 'success' && data.token) {
                TokenManager.setTokens(data.token, data.refresh_token);
                return true;
            }
            return false;
        } catch { return false; }
    }

    function handleAuthFailure() {
        TokenManager.clear();
        window.dispatchEvent(new CustomEvent('bkids:auth-failed'));
    }

    async function request(endpoint, options) {
        options = options || {};
        var lastError;

        for (var attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
            if (attempt > 0) {
                await sleep(RETRY_BASE_DELAY * attempt);
            }

            var url = API_BASE + endpoint;
            var controller = new AbortController();
            var tid = setTimeout(function() { controller.abort(); }, REQUEST_TIMEOUT);

            try {
                var response = await fetch(url, {
                    method: options.method || 'GET',
                    headers: buildHeaders(options.headers),
                    body: options.body || undefined,
                    credentials: 'same-origin',
                    signal: controller.signal,
                });
                clearTimeout(tid);

                if (response.status === 401) {
                    var refreshed = await tryRefreshToken();
                    if (refreshed) continue;
                    handleAuthFailure();
                    throw new ApiError('Phiên đăng nhập hết hạn. Vui lòng đăng nhập lại.', 401);
                }
                if (response.status === 403) throw new ApiError('Truy cập bị từ chối.', 403);
                if (response.status === 404) throw new ApiError('Không tìm thấy tài nguyên.', 404);
                if (response.status >= 500) {
                    lastError = new ApiError('Lỗi máy chủ (' + response.status + ').', response.status);
                    continue;
                }

                var data = await response.json();
                if (data.status === 'error' || data.success === false) {
                    throw new ApiError(data.message || 'Lỗi API.', response.status, data);
                }
                return data;

            } catch (error) {
                clearTimeout(tid);
                if (error instanceof ApiError) {
                    if (error.status >= 500) { lastError = error; continue; }
                    throw error;
                }
                if (error.name === 'AbortError') {
                    lastError = new ApiError('Yêu cầu hết thời gian chờ.', 0);
                    continue;
                }
                lastError = new ApiError('Lỗi mạng: ' + error.message, 0);
                continue;
            }
        }
        throw lastError || new ApiError('API không khả dụng.', 0);
    }

    // ========================================================================
    // API ERROR CLASS
    // ========================================================================

    class ApiError extends Error {
        constructor(message, status, data) {
            if (status === void 0) status = 0;
            if (data === void 0) data = null;
            super(message);
            this.name = 'ApiError';
            this.status = status;
            this.data = data;
        }
    }

    // ========================================================================
    // API ENDPOINTS — Tất cả đều qua request()
    // ========================================================================

    var API = {
        auth: {
            async login(username, password) {
                var data = await request('/auth/login', {
                    method: 'POST',
                    body: JSON.stringify({ username: username, password: password }),
                });
                if (data.status === 'success') {
                    TokenManager.setTokens(data.token, data.refresh_token);
                    TokenManager.setUser(data.user);
                }
                return data;
            },
            logout() { TokenManager.clear(); },
            async me() { return request('/auth/me'); },
        },

        alerts: {
            async getAlerts(limit, offset) {
                if (limit === void 0) limit = 250;
                if (offset === void 0) offset = 0;
                return request('/alerts?limit=' + encodeURIComponent(limit) + '&offset=' + encodeURIComponent(offset));
            },
            async getMisuseAlerts(limit, offset) {
                return this.getAlerts(limit, offset);
            },
            async getRecentAlerts(limit) {
                if (limit === void 0) limit = 50;
                return request('/alerts/recent?limit=' + encodeURIComponent(limit));
            },
            async getSummary() { return request('/alerts/summary'); },
            async getAnomalyData() {
                return request('/anomaly/realtime');
            },
            async getAnomalyConfig() {
                return request('/anomaly/config');
            },
            async setAnomalyConfig(threshold) {
                return request('/anomaly/config', {
                    method: 'POST',
                    body: JSON.stringify({ cusum_threshold: threshold })
                });
            },
            async getPacketDetails(ip, time) {
                var url = '/get_packet_details?ip=' + encodeURIComponent(ip);
                if (time) url += '&time=' + encodeURIComponent(time);
                return request(url);
            },
        },

        anomaly: {
            async getRealtime() {
                return request('/anomaly/realtime');
            }
        },

        soar: {
            async getActiveBlocks() { return request('/soar/blocks'); },
            async unblockIp(ip) {
                return request('/soar/unblock', { method: 'POST', body: JSON.stringify({ ip: ip }) });
            },
            async blockIp(ip) {
                return request('/soar/block', { method: 'POST', body: JSON.stringify({ ip: ip }) });
            },
            async updateBlockDuration(ip, duration) {
                return request('/soar/update_duration', { method: 'POST', body: JSON.stringify({ ip: ip, duration: duration }) });
            },
        },

        rules: {
            async getAll() { return request('/rules'); },
            async save(data) {
                return request('/rules/single', { method: 'POST', body: JSON.stringify(data) });
            },
            async saveBatch(data) {
                return request('/rules', { method: 'POST', body: JSON.stringify(data) });
            },
            async toggle(data) {
                return request('/rules/toggle', { method: 'PATCH', body: JSON.stringify(data) });
            },
            async deleteRule(data) {
                return request('/rules', { method: 'DELETE', body: JSON.stringify(data) });
            },
            async getBannedIPs() { return API.soar.getActiveBlocks(); },
            async unbanIp(ip) {
                return API.soar.unblockIp(ip);
            },
        },

        system: {
            async health() { return request('/health'); },
            async healthSystem() { return request('/health/system'); },
        },
    };

    // ========================================================================
    // EXPORTS
    // ========================================================================

    window.TokenManager = TokenManager;
    window.API = API;
    window.ApiError = ApiError;
    window.API_BASE = API_BASE;

})();
