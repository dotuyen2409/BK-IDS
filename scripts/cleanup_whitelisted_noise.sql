-- BK-IDS cleanup: remove already-ingested infrastructure noise.
-- Keep this list aligned with WHITELIST_IPS in .env.

USE bk_ids;

CREATE TEMPORARY TABLE IF NOT EXISTS tmp_bkids_whitelist_ips (
    ip VARCHAR(45) PRIMARY KEY
);

INSERT IGNORE INTO tmp_bkids_whitelist_ips (ip) VALUES
    ('127.0.0.1'),
    ('192.168.13.1'),
    ('192.168.13.128');

UPDATE soar_blocks
SET is_active = 0,
    unblocked_at = COALESCE(unblocked_at, NOW(3)),
    reason = CONCAT('[SUPPRESSED_WHITELIST] ', reason)
WHERE ip IN (SELECT ip FROM tmp_bkids_whitelist_ips)
  AND is_active = 1;

DELETE FROM alerts
WHERE src_ip IN (SELECT ip FROM tmp_bkids_whitelist_ips);

SELECT
    'cleanup_whitelisted_noise_complete' AS status,
    (SELECT COUNT(*) FROM alerts WHERE src_ip IN (SELECT ip FROM tmp_bkids_whitelist_ips)) AS remaining_alerts,
    (SELECT COUNT(*) FROM soar_blocks WHERE ip IN (SELECT ip FROM tmp_bkids_whitelist_ips) AND is_active = 1) AS remaining_active_blocks;
