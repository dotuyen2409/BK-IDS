-- /etc/snort/snort.lua
-- ========================================================================
-- BK-IDS SOC: Snort 3 NGIPS Configuration v12.0
-- ========================================================================

daq = {
    module_dirs = { "/usr/local/lib/daq" },
    modules = {
        { name = "afpacket", mode = "passive" }
    }
}

ipc = {}

HOME_NET = os.getenv("HOME_NET") or "192.168.13.0/24"
EXTERNAL_NET = "any"

ips = {
    enable_builtin_rules = false,
    variables = {
        nets = {
            HOME_NET       = HOME_NET,
            EXTERNAL_NET   = EXTERNAL_NET,
            HTTP_SERVERS   = "$HOME_NET",
            SMTP_SERVERS   = "$HOME_NET",
            TELNET_SERVERS = "$HOME_NET",
            FTP_SERVERS    = "$HOME_NET",
            SSH_SERVERS    = "$HOME_NET",
            SQL_SERVERS    = "$HOME_NET",
            DNS_SERVERS    = "$HOME_NET",
            POP_SERVERS    = "$HOME_NET",
            IMAP_SERVERS   = "$HOME_NET",
            SIP_SERVERS    = "$HOME_NET",
        },
        ports = {
            HTTP_PORTS       = "80 443 8080 8443 5000 5050 9000",
            FTP_PORTS        = "21",
            SSH_PORTS        = "22",
            TELNET_PORTS     = "23",
            SMTP_PORTS       = "25 465 587",
            FILE_DATA_PORTS  = "80 8080 5050 9000 110 143",
            SIP_PORTS        = "5060 5061",
            SQL_PORTS        = "1433 3306",
            ORACLE_PORTS     = "1521",
        },
    },
}

stream = {}
stream_tcp = { session_timeout = 180 }
stream_udp = { session_timeout = 60 }
stream_icmp = {}
stream_ip = {}
stream_user = {}
stream_file = {}

-- HTTP Inspector: QUAN TRỌNG cho content matching trên HTTP traffic
-- Snort 3 cần http_inspect để decode HTTP request trước khi match content
http_inspect = {
    request_depth = -1,   -- unlimited request body inspection
    response_depth = -1,  -- unlimited response body inspection
}

ftp_server = {}
ftp_client = {}
ftp_data = {}
smtp = {}
ssh = {}
dns = {}
ssl = {}
telnet = {}
sip = {}
pop = {}
imap = {}
-- arp_spoof = {}

-- Binder: gắn protocol inspector vào port tương ứng
binder = {
    { when = { proto = 'udp', ports = '53' },   use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '80' },   use = { type = 'http_inspect' } },
    { when = { proto = 'tcp', ports = '8080' }, use = { type = 'http_inspect' } },
    { when = { proto = 'tcp', ports = '5050' }, use = { type = 'http_inspect' } },
    { when = { proto = 'tcp', ports = '9000' }, use = { type = 'http_inspect' } },
    { when = { proto = 'tcp', ports = '5000' }, use = { type = 'http_inspect' } },
    { when = { proto = 'tcp', ports = '443' },  use = { type = 'ssl' } },
    { when = { proto = 'tcp', ports = '21' },   use = { type = 'ftp_server' } },
    { when = { proto = 'tcp', ports = '22' },   use = { type = 'ssh' } },
    { when = { proto = 'tcp', ports = '25' },   use = { type = 'smtp' } },
    { when = { proto = 'tcp' },                use = { type = 'stream_tcp' } },
    { when = { proto = 'udp' },                use = { type = 'stream_udp' } },
}

file_id = {}

-- port_scan = {}

event_filter = {}

-- AppID disabled (missing odp directory)
-- appid = {}

-- Reputation disabled (prevent startup crash)
-- reputation = {}

alert_json = {
    file   = true,
    limit  = 0,
}

suppress = {
    -- Suppress IGMP false positives (multicast traffic)
    { gid = 116, sid = 444 }
}

detection = {}

perf_monitor = {}
