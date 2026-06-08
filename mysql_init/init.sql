-- ============================================================
-- BK-IDS SOC: DATABASE SCHEMA — NGIPS Lean v3.0
-- Phase 1-3: Canonical alert model, SOAR tables, rule management
-- Mount to /docker-entrypoint-initdb.d/ in MySQL container
-- ============================================================

-- Ensure database exists
CREATE DATABASE IF NOT EXISTS bk_ids
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE bk_ids;

-- ============================================================
-- Table: alerts (CANONICAL — replaces misuse_alerts as source of truth)
-- Source: LogWatchdog parsing /var/log/snort/alert_json.txt
-- All alert queries MUST target this table.
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- Snort event time (from JSON timestamp field)
    event_time      DATETIME(3) NOT NULL COMMENT 'Alert event time from Snort',
    src_ip          VARCHAR(45)  NOT NULL DEFAULT '' COMMENT 'Source IP address',
    src_port        SMALLINT UNSIGNED DEFAULT NULL COMMENT 'Source port (NULL for ICMP/non-port)',
    dst_ip          VARCHAR(45)  NOT NULL DEFAULT '' COMMENT 'Destination IP address',
    dst_port        SMALLINT UNSIGNED DEFAULT NULL COMMENT 'Destination port',
    protocol        VARCHAR(10)  NOT NULL DEFAULT 'tcp' COMMENT 'Protocol: tcp/udp/icmp/ip',
    -- Snort rule fields
    sid             INT UNSIGNED DEFAULT 0 COMMENT 'Snort Rule SID',
    gid             INT UNSIGNED DEFAULT 1 COMMENT 'Snort Rule GID',
    rev             INT UNSIGNED DEFAULT 1 COMMENT 'Rule revision',
    signature       VARCHAR(512) NOT NULL DEFAULT '' COMMENT 'Rule msg / signature name',
    category        VARCHAR(100) DEFAULT '' COMMENT 'Classtype / category (e.g., port-scan, reputation)',
    severity        ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    action          VARCHAR(20)  NOT NULL DEFAULT 'alert' COMMENT 'Snort action: alert/drop/block',
    -- Layer 7 enrichment (from OpenAppID)
    app_id          VARCHAR(100) DEFAULT NULL COMMENT 'OpenAppID application name',
    -- Raw data preservation
    raw_json        JSON         DEFAULT NULL COMMENT 'Full raw alert JSON from Snort',
    -- Deduplication: prevents duplicate inserts for same event
    dedupe_hash     CHAR(64)     NOT NULL COMMENT 'SHA256(timestamp+src_ip+dst_ip+sid+action)',
    -- SOAR link
    soar_blocked    TINYINT(1)   DEFAULT 0 COMMENT '1 if SOAR auto-blocked the source IP',
    -- Record timestamps
    created_at      TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP(3),

    -- Indexes for dashboard query patterns
    UNIQUE KEY uq_dedupe (dedupe_hash),
    INDEX idx_event_time  (event_time),
    INDEX idx_src_ip      (src_ip),
    INDEX idx_dst_ip      (dst_ip),
    INDEX idx_severity    (severity),
    INDEX idx_action      (action),
    INDEX idx_category    (category),
    INDEX idx_sid         (sid),
    INDEX idx_soar_blocked (soar_blocked),
    -- Composite for recent-by-src-ip SOAR lookups
    INDEX idx_src_severity (src_ip, severity, event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Canonical alert table — source: Snort 3 alert_json via LogWatchdog';

-- ============================================================
-- Compatibility view: misuse_alerts → alerts
-- Keeps legacy API endpoints working without code changes.
-- Drop this view once all API paths reference `alerts` directly.
-- ============================================================
CREATE OR REPLACE VIEW misuse_alerts AS
    SELECT
        id,
        event_time          AS timestamp,
        src_ip              AS ip_src,
        signature           AS sig_name,
        protocol,
        UPPER(action)       AS action,
        created_at
    FROM alerts;

-- ============================================================
-- Table: rules
-- Purpose: Manage Snort IDS/IPS rules (custom + pulled)
-- Source: rules_controller.py get_rules(), save_rules()
-- ============================================================
CREATE TABLE IF NOT EXISTS rules (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sid             INT UNSIGNED NOT NULL UNIQUE COMMENT 'Snort Rule SID',
    rev             INT UNSIGNED DEFAULT 1 COMMENT 'Revision',
    gid             INT UNSIGNED DEFAULT 1 COMMENT 'Generator ID',
    action          VARCHAR(10)  NOT NULL DEFAULT 'alert' COMMENT 'alert/drop/pass/reject',
    protocol        VARCHAR(10)  NOT NULL DEFAULT 'tcp',
    src_net         VARCHAR(100) DEFAULT 'any',
    src_port        VARCHAR(100) DEFAULT 'any',
    dst_net         VARCHAR(100) DEFAULT 'any',
    dst_port        VARCHAR(55)  DEFAULT 'any',
    msg             VARCHAR(512) DEFAULT '' COMMENT 'Rule message',
    classtype       VARCHAR(100) DEFAULT '' COMMENT 'Rule classtype',
    priority        TINYINT UNSIGNED DEFAULT 2,
    raw_rule        TEXT         COMMENT 'Full raw Snort rule text',
    source          VARCHAR(50)  DEFAULT 'local_custom' COMMENT 'local_custom/et_open/pulled',
    is_active       TINYINT(1)   DEFAULT 1,
    created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sid       (sid),
    INDEX idx_source    (source),
    INDEX idx_is_active (is_active),
    INDEX idx_classtype (classtype)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Snort rule management table';

-- ============================================================
-- Table: soar_blocks
-- Purpose: Track active and historical SOAR IP blocks
-- Source: soar_engine.py block/unblock actions
-- ============================================================
CREATE TABLE IF NOT EXISTS soar_blocks (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip              VARCHAR(45)  NOT NULL COMMENT 'Blocked IP address',
    reason          VARCHAR(512) DEFAULT '' COMMENT 'Block reason / alert summary',
    alert_id        BIGINT UNSIGNED DEFAULT NULL COMMENT 'FK to alerts.id that triggered block',
    blocked_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    unblocked_at    DATETIME(3)  DEFAULT NULL COMMENT 'NULL = still active',
    ban_duration_sec INT UNSIGNED DEFAULT 3600,
    source          VARCHAR(50)  DEFAULT 'soar_auto' COMMENT 'soar_auto/manual',
    is_active       TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '1=active block',
    INDEX idx_ip        (ip),
    INDEX idx_is_active (is_active),
    INDEX idx_blocked_at (blocked_at),
    FOREIGN KEY fk_alert (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='SOAR active and historical IP blocks';

-- ============================================================
-- Table: soar_audit
-- Purpose: Immutable audit log for all SOAR actions
-- Source: soar_engine._audit() → db write
-- ============================================================
CREATE TABLE IF NOT EXISTS soar_audit (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    action_time     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    action          VARCHAR(50)  NOT NULL COMMENT 'BLOCK_IP/UNBLOCK_IP/RATE_LIMITED/WHITELISTED/ALERT_ONLY',
    ip              VARCHAR(45)  NOT NULL,
    reason          VARCHAR(512) DEFAULT '',
    source          VARCHAR(50)  DEFAULT 'soar',
    success         TINYINT(1)   NOT NULL DEFAULT 1,
    details         TEXT         DEFAULT NULL,
    operator        VARCHAR(100) DEFAULT 'system' COMMENT 'system or authenticated user',
    INDEX idx_action_time (action_time),
    INDEX idx_ip          (ip),
    INDEX idx_action      (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Immutable audit log for all SOAR block/unblock actions';

-- ============================================================
-- Table: ids_dulieu (retained for historical CUSUM data)
-- NOTE: This table is NO LONGER written to by active components.
-- Retained only for historical query compatibility.
-- Will be deprecated after data migration window.
-- ============================================================
CREATE TABLE IF NOT EXISTS ids_dulieu (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    tg_batdau       DATETIME NOT NULL,
    tg_ketthuc      DATETIME NOT NULL,
    soluong_tcp     INT UNSIGNED DEFAULT 0,
    soluong_udp     INT UNSIGNED DEFAULT 0,
    soluong_icmp    INT UNSIGNED DEFAULT 0,
    Gn              DECIMAL(10,2) DEFAULT 0.00,
    entropi         DECIMAL(8,3) DEFAULT 0.000,
    top_ip          VARCHAR(45) DEFAULT 'Unknown',
    sample_hex      TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tg_batdau (tg_batdau),
    INDEX idx_top_ip (top_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='[LEGACY] Historical CUSUM anomaly data — read-only, no new writes';

-- ============================================================
-- Seed: Sample rules for local.rules testing
-- ============================================================
INSERT IGNORE INTO rules (sid, rev, action, protocol, src_net, src_port, dst_net, dst_port, msg, classtype, priority, raw_rule, source) VALUES
  (1000001, 1, 'drop', 'tcp', 'any', 'any', '$HOME_NET', '80', 'SQL Injection Attempt - UNION SELECT', 'web-application-attack', 1,
   'drop tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt - UNION SELECT"; content:"union select",nocase; classtype:web-application-attack; sid:1000001; rev:1;)',
   'local_custom'),
  (1000002, 1, 'alert', 'tcp', 'any', 'any', '$HOME_NET', '80', 'XSS Reflected Attack Attempt', 'web-application-attack', 2,
   'alert tcp any any -> $HOME_NET 80 (msg:"XSS Reflected Attack Attempt"; content:"<script>",nocase; classtype:web-application-attack; sid:1000002; rev:1;)',
   'local_custom'),
  (1000003, 1, 'drop', 'tcp', 'any', 'any', '$HOME_NET', 'any', 'Log4j JNDI Injection RCE Attempt', 'web-application-attack', 1,
   'drop tcp any any -> $HOME_NET any (msg:"Log4j JNDI Injection RCE Attempt"; content:"${jndi:",nocase; classtype:web-application-attack; sid:1000003; rev:1;)',
   'local_custom'),
  (1000004, 1, 'alert', 'tcp', '$EXTERNAL_NET', 'any', '$HOME_NET', '22', 'SSH Brute Force Attempt', 'attempted-admin', 2,
   'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; threshold:type threshold,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000004; rev:1;)',
   'local_custom'),
  (1000005, 1, 'alert', 'icmp', 'any', 'any', '$HOME_NET', 'any', 'ICMP Ping Sweep Detection', 'network-scan', 3,
   'alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep Detection"; itype:8; threshold:type threshold,track by_src,count 10,seconds 5; classtype:network-scan; sid:1000005; rev:1;)',
   'local_custom');

-- ============================================================
-- Seed: Sample alerts for dashboard testing
-- ============================================================
INSERT IGNORE INTO alerts (event_time, src_ip, src_port, dst_ip, dst_port, protocol, sid, gid, rev, signature, category, severity, action, app_id, dedupe_hash) VALUES
  (NOW() - INTERVAL 15 MINUTE, '45.33.32.156',  54321, '192.168.13.129', 80, 'tcp', 1000001, 1, 1, 'SQL Injection Attempt - UNION SELECT', 'web-application-attack', 'high',    'drop',  'HTTP', SHA2(CONCAT('15min-ago','45.33.32.156','192.168.13.129','1000001','drop'), 256)),
  (NOW() - INTERVAL 12 MINUTE, '185.220.101.34', 44444, '192.168.13.129', 80, 'tcp', 1000002, 1, 1, 'XSS Reflected Attack Attempt',        'web-application-attack', 'medium',  'alert', 'HTTP', SHA2(CONCAT('12min-ago','185.220.101.34','192.168.13.129','1000002','alert'), 256)),
  (NOW() - INTERVAL 8 MINUTE,  '103.224.182.250', 33333, '192.168.13.129', 22, 'tcp', 1000004, 1, 1, 'SSH Brute Force Attempt',             'attempted-admin',        'critical', 'alert', 'SSH',  SHA2(CONCAT('8min-ago','103.224.182.250','192.168.13.129','1000004','alert'), 256)),
  (NOW() - INTERVAL 3 MINUTE,  '10.0.0.55',      22222, '192.168.13.129', 80, 'tcp', 1000003, 1, 1, 'Log4j JNDI Injection RCE Attempt',    'web-application-attack', 'critical', 'drop',  'HTTP', SHA2(CONCAT('3min-ago','10.0.0.55','192.168.13.129','1000003','drop'), 256));
