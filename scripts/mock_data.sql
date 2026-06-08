-- BK-IDS SOC: Mock data cho testing pipeline
-- Chạy: docker exec -i bkids_mysql mysql -u root -pBk!ds_MySQ bk_ids < mock_data.sql

USE bk_ids;

-- Mock Snort alerts
INSERT INTO alerts (event_time, src_ip, src_port, dst_ip, dst_port, protocol, sid, signature, category, severity, action, app_id, soar_blocked) VALUES
(NOW() - INTERVAL 1 MINUTE,  '10.0.0.55', 54321, '192.168.13.100', 80,  'TCP', 1001001, '[BLOCK] SQLi UNION SELECT extraction',     'web-application-attack', 'high',   'drop',   'http', 0),
(NOW() - INTERVAL 3 MINUTE,  '10.0.0.55', 54322, '192.168.13.100', 443, 'TCP', 1001002, '[BLOCK] SQLi OR-based bypass',            'web-application-attack', 'high',   'drop',   'https', 0),
(NOW() - INTERVAL 5 MINUTE,  '172.16.0.10', 12345, '192.168.13.100', 22,  'TCP', 1004001, '[RECON] SSH brute force attempt',          'attempted-admin',        'medium', 'alert',  'ssh', 0),
(NOW() - INTERVAL 7 MINUTE,  '10.0.0.99', 8080,  '192.168.13.100', 3306,'TCP', 1001005, '[BLOCK] SQLi xp_cmdshell MSSQL exec',     'web-application-attack', 'critical','drop',  'mysql', 1),
(NOW() - INTERVAL 10 MINUTE, '192.168.13.50', 44444,'192.168.13.100', 80, 'TCP', 1002001, '[ALERT] XSS script tag injection',        'web-application-attack', 'medium', 'alert',  'http', 0),
(NOW() - INTERVAL 15 MINUTE, '10.0.0.77', 38900, '192.168.13.100', 443, 'TCP', 1003001, '[ALERT] Path Traversal ../ escape',        'web-application-attack', 'medium', 'alert',  'https', 0),
(NOW() - INTERVAL 20 MINUTE, '172.16.0.20', 22222,'192.168.13.100', 22,  'TCP', 1004001, '[RECON] SSH brute force attempt',          'attempted-admin',        'medium', 'alert',  'ssh', 0),
(NOW() - INTERVAL 25 MINUTE, '10.0.0.55', 54323, '192.168.13.100', 80,  'TCP', 1001004, '[BLOCK] SQLi SLEEP time-based blind',      'web-application-attack', 'high',   'drop',   'http', 0),
(NOW() - INTERVAL 30 MINUTE, '10.0.0.200', 11111,'192.168.13.100', 5060,'UDP', 1005001, '[C2] Suspicious SIP registration',        'trojan-activity',        'critical','alert',  'sip', 1),
(NOW() - INTERVAL 35 MINUTE, '192.168.13.200', 2222,'192.168.13.100', 80,  'TCP', 1002002, '[ALERT] XSS javascript URI scheme',       'web-application-attack', 'low',    'alert',  'http', 0);

-- Mock SOAR blocks
INSERT INTO soar_blocks (ip, reason, source, blocked_at, is_active, ban_duration_sec) VALUES
('10.0.0.99',  'SOAR auto-block: SQLi xp_cmdshell',     'snort', NOW() - INTERVAL 7 MINUTE,  1, 3600),
('10.0.0.200', 'SOAR auto-block: C2 SIP registration',  'snort', NOW() - INTERVAL 30 MINUTE, 1, 3600);

-- Mock CuSUM anomaly data
INSERT INTO ids_dulieu (tg_batdau, tg_ketthuc, soluong_tcp, soluong_udp, soluong_icmp, Gn, entropi, top_ip, sample_hex) VALUES
(NOW() - INTERVAL 2 MINUTE,  NOW() - INTERVAL 1 MINUTE,  150, 30, 5,  850.5,  7.234, '10.0.0.55',  '[DDoS] SYN flood detected'),
(NOW() - INTERVAL 5 MINUTE,  NOW() - INTERVAL 4 MINUTE,  200, 45, 12, 920.1,  7.891, '10.0.0.99',  '[DDoS] UDP amplification'),
(NOW() - INTERVAL 8 MINUTE,  NOW() - INTERVAL 7 MINUTE,  80,  15, 2,  450.3,  5.123, '172.16.0.10', '[BÌNH THƯỜNG] Normal traffic'),
(NOW() - INTERVAL 12 MINUTE, NOW() - INTERVAL 11 MINUTE, 300, 60, 20, 1100.8, 8.456, '10.0.0.200', '[C2] Beaconing pattern detected'),
(NOW() - INTERVAL 15 MINUTE, NOW() - INTERVAL 14 MINUTE, 50,  10, 1,  200.0,  3.567, '192.168.13.50', '[BÌNH THƯỜNG] Normal traffic'),
(NOW() - INTERVAL 20 MINUTE, NOW() - INTERVAL 19 MINUTE, 180, 35, 8,  780.2,  6.789, '10.0.0.77',  '[RECON] Port scan detected'),
(NOW() - INTERVAL 25 MINUTE, NOW() - INTERVAL 24 MINUTE, 90,  20, 3,  350.5,  4.234, '172.16.0.20', '[HẠ NHIỆT] Cooling down'),
(NOW() - INTERVAL 30 MINUTE, NOW() - INTERVAL 29 MINUTE, 250, 50, 15, 950.7,  7.567, '10.0.0.55',  '[DDoS] HTTP flood detected');

SELECT 'Mock data inserted: 10 alerts, 2 soar_blocks, 8 anomaly records' AS status;
