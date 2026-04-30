-- -- /home/bk_ids/bk-ids/snort.lua

--------------------------------------------------
-- BK-IDS NETWORK VARIABLES (FIX ALL RULE ERRORS)
--------------------------------------------------

-- HOME_NET = '192.168.142.0/24'
-- EXTERNAL_NET = 'any'

-- HTTP_SERVERS   = HOME_NET
-- SMTP_SERVERS   = HOME_NET
-- TELNET_SERVERS = HOME_NET
-- FTP_SERVERS    = HOME_NET
-- SSH_SERVERS    = HOME_NET
-- SQL_SERVERS    = HOME_NET
-- DNS_SERVERS    = HOME_NET
-- POP_SERVERS    = HOME_NET
-- IMAP_SERVERS   = HOME_NET
-- SIP_SERVERS    = HOME_NET

-- HTTP_PORTS  = '80 8080 443'
-- FTP_PORTS   = '21'
-- SSH_PORTS   = '22'
-- TELNET_PORTS= '23'
-- SMTP_PORTS  = '25 465 587'
-- FILE_DATA_PORTS = '80 110 143'
-- SIP_PORTS   = '5060 5061'
-- SQL_PORTS   = '1433 3306'
-- ORACLE_PORTS= '1521'

--------------------------------------------------
-- BK-IDS NETWORK VARIABLES (SNORT 3 FORMAT)
--------------------------------------------------
ips = {
    variables = {
        nets = {
            HOME_NET = '192.168.142.0/24',
            EXTERNAL_NET = 'any',
            HTTP_SERVERS = '$HOME_NET',
            SMTP_SERVERS = '$HOME_NET',
            TELNET_SERVERS = '$HOME_NET',
            FTP_SERVERS = '$HOME_NET',
            SSH_SERVERS = '$HOME_NET',
            SQL_SERVERS = '$HOME_NET',
            DNS_SERVERS = '$HOME_NET',
            POP_SERVERS = '$HOME_NET',
            IMAP_SERVERS = '$HOME_NET',
            SIP_SERVERS = '$HOME_NET'
        },
        ports = {
            HTTP_PORTS = '80 8080 5000', -- Đã thêm port 5000 của Flask API
            FTP_PORTS = '21',
            SSH_PORTS = '22',
            TELNET_PORTS = '23',
            SMTP_PORTS = '25 465 587',
            FILE_DATA_PORTS = '80 8080 110 143',
            SIP_PORTS = '5060 5061',
            SQL_PORTS = '1433 3306',
            ORACLE_PORTS = '1521'
        }
    }
}