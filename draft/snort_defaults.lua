-- /home/bk_ids/bk-ids/snort_defaults.lua
    default_variables =
    {
        nets =
        {
            HOME_NET = '192.168.142.0/24',
            EXTERNAL_NET = 'any',

            HTTP_SERVERS   = HOME_NET,
            SMTP_SERVERS   = HOME_NET,
            TELNET_SERVERS = HOME_NET,
            FTP_SERVERS    = HOME_NET,
            SSH_SERVERS    = HOME_NET,
            SQL_SERVERS    = HOME_NET,
            DNS_SERVERS    = HOME_NET,
            POP_SERVERS    = HOME_NET,
            IMAP_SERVERS   = HOME_NET,
            SIP_SERVERS    = HOME_NET
        },

        ports =
        {
            HTTP_PORTS      = '80 8080 443',
            FTP_PORTS       = '21',
            SSH_PORTS       = '22',
            TELNET_PORTS    = '23',
            SMTP_PORTS      = '25 465 587',
            FILE_DATA_PORTS = '80 8080 443 110 143',
            SIP_PORTS       = '5060 5061 5062',
            SQL_PORTS       = '1433 3306',
            ORACLE_PORTS    = '1521'
        }
    }
    