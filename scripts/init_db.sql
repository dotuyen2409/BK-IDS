-- Khởi tạo Database nếu chưa có và chuyển vào sử dụng
CREATE DATABASE IF NOT EXISTS bk_ids CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE bk_ids;

-- ==========================================
-- PHẦN 1: HỆ THỐNG PHÂN QUYỀN & NGƯỜI DÙNG
-- ==========================================
CREATE TABLE IF NOT EXISTS base_roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL,
    role_desc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS base_users (
    usr_id INT AUTO_INCREMENT PRIMARY KEY,
    usr_login VARCHAR(50) NOT NULL UNIQUE,
    usr_pwd VARCHAR(255) NOT NULL, -- Đã mở rộng độ dài để lưu chuỗi Hash mật khẩu an toàn
    usr_name VARCHAR(100) NOT NULL,
    role_id INT NOT NULL,
    usr_enabled TINYINT(1) DEFAULT 1,
    FOREIGN KEY (role_id) REFERENCES base_roles(role_id) ON DELETE CASCADE
);

-- ==========================================
-- PHẦN 2: TỪ ĐIỂN CHỮ KÝ & CẢM BIẾN (SENSOR)
-- ==========================================
CREATE TABLE IF NOT EXISTS encoding (
    encoding_type INT PRIMARY KEY,
    encoding_text VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS signature (
    sig_id INT AUTO_INCREMENT PRIMARY KEY,
    sig_name VARCHAR(255) NOT NULL,
    sig_class_id INT NOT NULL,
    sig_priority INT,
    sig_rev INT,
    sig_sid INT,
    sig_gid INT,
    INDEX idx_sig_name (sig_name)
);

CREATE TABLE IF NOT EXISTS sensor (
    sid INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(255),
    interface VARCHAR(50),
    filter VARCHAR(255),
    detail INT,
    encoding INT,
    last_cid BIGINT,
    FOREIGN KEY (encoding) REFERENCES encoding(encoding_type)
);

-- ==========================================
-- PHẦN 3: HỆ THỐNG BẮT GÓI TIN & TIỀN XỬ LÝ
-- ==========================================
CREATE TABLE IF NOT EXISTS event (
    sid INT NOT NULL,
    cid BIGINT AUTO_INCREMENT PRIMARY KEY,
    signature INT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sid) REFERENCES sensor(sid),
    FOREIGN KEY (signature) REFERENCES signature(sig_id),
    INDEX idx_timestamp (timestamp)
);

CREATE TABLE IF NOT EXISTS data (
    sid INT NOT NULL,
    cid BIGINT NOT NULL,
    data_payload TEXT,
    PRIMARY KEY (cid),
    FOREIGN KEY (cid) REFERENCES event(cid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iphdr (
    sid INT NOT NULL,
    cid BIGINT NOT NULL,
    ip_src VARCHAR(45) NOT NULL, -- Chuẩn IPv6
    ip_dst VARCHAR(45) NOT NULL,
    ip_ver INT,
    ip_hlen INT,
    ip_tos INT,
    ip_len INT,
    ip_id INT,
    ip_flags INT,
    ip_off INT,
    ip_ttl INT,
    ip_proto INT NOT NULL,
    ip_csum INT,
    PRIMARY KEY (cid),
    FOREIGN KEY (cid) REFERENCES event(cid) ON DELETE CASCADE,
    INDEX idx_ip_src (ip_src),
    INDEX idx_ip_dst (ip_dst)
);

CREATE TABLE IF NOT EXISTS tcphdr (
    sid INT NOT NULL,
    cid BIGINT NOT NULL,
    tcp_sport INT NOT NULL,
    tcp_dport INT NOT NULL,
    tcp_seq BIGINT,
    tcp_ack BIGINT,
    tcp_off INT,
    tcp_res INT,
    tcp_flags INT NOT NULL,
    tcp_win INT,
    tcp_csum INT,
    tcp_urp INT,
    PRIMARY KEY (cid),
    FOREIGN KEY (cid) REFERENCES event(cid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS udphdr (
    sid INT NOT NULL,
    cid BIGINT NOT NULL,
    udp_sport INT NOT NULL,
    udp_dport INT NOT NULL,
    udp_len INT,
    udp_csum INT,
    PRIMARY KEY (cid),
    FOREIGN KEY (cid) REFERENCES event(cid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS icmphdr (
    sid INT NOT NULL,
    cid BIGINT NOT NULL,
    icmp_type INT NOT NULL,
    icmp_code INT NOT NULL,
    icmp_csum INT,
    icmp_id INT NOT NULL,
    icmp_seq INT NOT NULL,
    PRIMARY KEY (cid),
    FOREIGN KEY (cid) REFERENCES event(cid) ON DELETE CASCADE
);

-- ==========================================
-- PHẦN 4: HỆ THỐNG PHÁT HIỆN LẠM DỤNG (ALERTS)
-- ==========================================
CREATE TABLE IF NOT EXISTS acid_event (
    cid BIGINT PRIMARY KEY AUTO_INCREMENT,
    sid INT,
    signature INT NOT NULL,
    sig_name VARCHAR(255),
    sig_class_id VARCHAR(255),
    sig_priority INT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_src VARCHAR(45) NOT NULL,
    ip_dst VARCHAR(45) NOT NULL,
    ip_proto INT,
    layer4_sport INT,
    layer4_dport INT,
    FOREIGN KEY (signature) REFERENCES signature(sig_id),
    INDEX idx_acid_time (timestamp),
    INDEX idx_acid_ip (ip_src)
);

CREATE TABLE IF NOT EXISTS acid_ip_cache (
    ipc_ip VARCHAR(45) PRIMARY KEY,
    ipc_fqdn VARCHAR(255),
    ipc_dns_timestamp DATETIME,
    ipc_whois TEXT,
    ipc_whois_timestamp DATETIME
);

-- ==========================================
-- PHẦN 5: HỆ THỐNG PHÁT HIỆN BẤT THƯỜNG
-- ==========================================
CREATE TABLE IF NOT EXISTS ids_cauhinh (
    id INT AUTO_INCREMENT PRIMARY KEY,
    thoigian_quet INT NOT NULL,
    nguong FLOAT NOT NULL,
    thoigian_hientai DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ids_dulieu (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    soluong_tcp INT NOT NULL,
    soluong_udp INT NOT NULL,
    soluong_icmp INT NOT NULL,
    tg_batdau DATETIME NOT NULL,
    tg_ketthuc DATETIME NOT NULL,
    Si FLOAT,
    Gn FLOAT,
    entropi TEXT,
    INDEX idx_thongke_thoi_gian (tg_batdau, tg_ketthuc)
);