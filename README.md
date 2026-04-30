<div align="center">

# 🛡️ BK-IDS SOC: ENTERPRISE HYBRID DETECTION SYSTEM
### *Lõi Bảo mật Phân tích Luồng dữ liệu và Ngăn chặn Tấn công Thời gian thực*

[![Version](https://img.shields.io/badge/Version-1.0.0--Stable-0ea5e9?style=for-the-badge)](https://github.com/dotuyen2409/bk_ids)
[![Engine](https://img.shields.io/badge/Engine-Snort%203.10-ef4444?style=for-the-badge)](https://www.snort.org/)
[![Stack](https://img.shields.io/badge/Stack-Python%20|%20VueJS%20|%20Docker-3b82f6?style=for-the-badge)]()
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-10b981?style=for-the-badge)]()

**BK-IDS SOC** là một hệ thống Hybrid IDS/IPS (Phát hiện và Ngăn chặn xâm nhập lai) cấp độ doanh nghiệp. Hệ thống kết hợp sức mạnh của phân tích chữ ký truyền thống và thuật toán phân tích bất thường dựa trên hành vi, mang lại lớp phòng thủ thép cho hạ tầng máy chủ.

[Khám phá Dashboard](#-giao-diện-giám-sát) • [Kiến trúc](#-kiến-trúc-hệ-thống) • [Hướng dẫn cài đặt](#-hướng-dẫn-triển-khai) • [Tính năng](#-tính- năng-cốt-lõi)

</div>

---

## 🚀 Tính năng cốt lõi (Core Capabilities)

Dự án này vượt xa các hệ thống giám sát thông thường bằng cách tích hợp các công nghệ tiên tiến nhất:

* **Lõi IPS Nội tuyến (Inline Snort 3 Engine):** Sử dụng `DAQNfq` và `Iptables` để bóp nát (DROP) các gói tin độc hại ngay tại tầng mạng trước khi chúng kịp tiếp cận ứng dụng.
* **Phát hiện Bất thường CuSUM:** Tích hợp thuật toán thống kê *Cumulative Sum* (CuSUM) và phân tích *Entropy* để phát hiện các đợt quét cổng (Port Scan), tấn công DoS/DDoS hoặc các hành vi bất thường chưa có trong bộ luật.
* **Máy chém Tường lửa tự động (Auto-Ban):** Cơ chế Python thông minh tự động trích xuất IP kẻ tấn công và phong tỏa toàn diện thông qua Iptables trong một khoảng thời gian cấu hình được.
* **Báo cáo DPI (Deep Packet Inspection):** Cho phép chuyên viên bảo mật "mổ xẻ" từng byte dữ liệu của gói tin bị chặn để phân tích Forensic chuyên sâu.
* **Hệ thống API Gateway Bọc thép:** Backend Python được thiết kế với cơ chế phòng thủ chiều sâu, chống lỗi I/O và tối ưu hóa Telemetry thời gian thực.

---

## 🏗️ Kiến trúc Hệ thống (System Architecture)

Hệ thống được thiết kế theo mô hình Microservices đóng gói hoàn toàn trong Docker:

1.  **Sensor Core (Snort 3):** Chạy ở chế độ Inline IPS, là lớp phòng thủ vòng ngoài.
2.  **Anomaly Engine:** Chạy song song để tính toán chỉ số Entropy và CuSUM từ luồng dữ liệu thô.
3.  **Database Cluster (MySQL):** Lưu trữ tập trung các cảnh báo, cấu hình luật và dữ liệu phân tích.
4.  **API Gateway (Flask):** Cầu nối trung tâm, điều phối dữ liệu và điều khiển Iptables.
5.  **SOC Dashboard (Vue.js 3):** Giao diện Glassmorphism hiện đại dành cho quản trị viên vận hành (SOC Tier 1/2).

---

## 🛠️ Công nghệ sử dụng (Technology Stack)

| Thành phần | Công nghệ |
| :--- | :--- |
| **Backend** | Python 3.11, Flask Framework, PyMySQL, Psutil |
| **Frontend** | Vue.js 3 (Composition API), Chart.js, CSS Glassmorphism |
| **Security Core** | Snort 3.x (C++), Libdaq, NetfilterQueue (NFQ) |
| **Hạ tầng** | Docker, Docker Compose, Linux Iptables |
| **Cơ sở dữ liệu** | MySQL 8.0 Enterprise |

---

## 📦 Hướng dẫn triển khai (Deployment Guide)

### Yêu cầu hệ thống
* **Hệ điều hành:** Ubuntu 22.04 LTS hoặc Linux tương đương.
* **Công cụ:** Docker & Docker Compose đã cài đặt.
* **Quyền hạn:** Cần quyền `sudo` để can thiệp Iptables.

### Các bước thực hiện
1. **Clone mã nguồn:**
   ```bash
   git clone [https://github.com/dotuyen2409/bk_ids.git](https://github.com/dotuyen2409/bk_ids.git)
   cd bk_ids