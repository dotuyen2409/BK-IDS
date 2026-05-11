<div align="center">

# BK-IDS SOC: ENTERPRISE HYBRID DETECTION SYSTEM
### *Lõi Bảo mật Phân tích Luồng dữ liệu và Ngăn chặn Tấn công Thời gian thực*

[![Version](https://img.shields.io/badge/Version-1.0.0--Stable-0ea5e9?style=for-the-badge)](https://github.com/dotuyen2409/bk_ids)
[![Engine](https://img.shields.io/badge/Engine-Snort%203.10-ef4444?style=for-the-badge)](https://www.snort.org/)
[![Stack](https://img.shields.io/badge/Stack-Python%20|%20VueJS%20|%20Docker-3b82f6?style=for-the-badge)]()
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-10b981?style=for-the-badge)]()

**BK-IDS SOC** là một hệ thống Hybrid IDS/IPS (Phát hiện và Ngăn chặn xâm nhập lai) cấp độ doanh nghiệp. Hệ thống là sự giao thoa hoàn hảo giữa sức mạnh của bộ máy phân tích chữ ký tốc độ cao (Misuse Detection) và thuật toán phân tích bất thường dựa trên hành vi thống kê (Anomaly Detection), mang lại một lớp "phòng thủ thép" chủ động cho hạ tầng máy chủ ứng dụng.

[Khám phá Dashboard](#-giao-diện-giám-sát-soc-dashboard) • [Kiến trúc](#%EF%B8%8F-kiến-trúc-hệ-thống-system-architecture) • [Hướng dẫn cài đặt](#-hướng-dẫn-triển-khai-deployment-guide) • [Tài liệu API](#-tích-hợp-và-mở-rộng-api)

</div>

---

##  Tính năng cốt lõi (Core Capabilities)

Dự án này vượt xa các hệ thống phát hiện xâm nhập thụ động (Passive IDS) thông thường bằng cách tích hợp trực tiếp khả năng can thiệp luồng mạng theo thời gian thực:

*  **Lõi IPS Nội tuyến (Inline Snort 3 Engine):** Triển khai Snort 3 ở chế độ `Inline` thông qua mô-đun Data Acquisition (DAQ) `nfq`. Hệ thống đoạt quyền kiểm soát gói tin trực tiếp từ Iptables, cho phép "bóp nát" (DROP) các luồng mã độc ngay tại không gian hạt nhân (Kernel Space) trước khi chúng kịp tiếp cận ứng dụng đích.
*  **Phát hiện Bất thường Toán học (CUSUM & Entropy):** Bổ khuyết cho các lỗ hổng Zero-day bằng cách tích hợp thuật toán thống kê *Cumulative Sum* (CUSUM) nhằm đo lường sự bùng nổ khối lượng lưu lượng, kết hợp cùng chỉ số *H-Entropy* để phân tích mức độ phân tán IP. Tự động nhận diện chính xác các chiến dịch quét mạng (Port Scan) và tấn công Từ chối dịch vụ (DoS/DDoS).
*  **Máy chém Tường lửa Tự động hóa (SOAR / Auto-Mitigation):** Tiến trình Python nội trú liên tục giám sát log sự kiện. Khi phát hiện luồng dữ liệu đạt ngưỡng nguy hiểm, hệ thống tự động trích xuất IP nguồn và chèn chỉ thị cấm (DROP) vào `Iptables` trong một khung thời gian (Ban Duration) được cấu hình động.
*  **Phân tích Chuyên sâu (Deep Packet Inspection - DPI):** Cung cấp bộ công cụ Forensic cho phép các chuyên viên phân tích SOC (Tier 2/3) "mổ xẻ" tải trọng gói tin (Payload) ở định dạng HEX và ASCII để truy vết hành vi tấn công.
*  **Hệ thống Cảnh báo Đa kênh:** Tích hợp cơ chế cảnh báo thời gian thực qua Web Socket và Telegram Bot, đảm bảo đội ngũ phản ứng sự cố (Incident Response) luôn nhận được thông tin trong vòng dưới 1 giây.

---

##  Kiến trúc Hệ thống (System Architecture)

BK-IDS được thiết kế theo tư tưởng **Microservices (Vi dịch vụ)**, tận dụng sức mạnh của công nghệ Container hóa để đảm bảo tính cô lập, dễ dàng mở rộng và phục hồi sau sự cố (Fault Tolerance).

Hệ sinh thái bao gồm 5 cấu phần chính:

1.  **Sensor Core (Snort 3):** Khối động cơ phân tích mạng tốc độ cao (C++). Hoạt động ở chế độ Inline, nhận gói tin từ hàng đợi số 0 (`--queue-num 0`).
2.  **Anomaly Engine:** Cụm thuật toán phân tích bất thường chạy song song, xử lý dữ liệu thô để trích xuất các vector đặc trưng (Feature Extraction) phục vụ thuật toán CuSUM.
3.  **Database Cluster (MySQL 8.0):** Kho lưu trữ tập trung. Phân vùng dữ liệu thông minh giữa các bảng cấu hình (Rules), Logs sự kiện (Misuse Alerts) và Dữ liệu chuỗi thời gian (Metrics).
4.  **API Gateway (Python/Flask):** Lõi điều phối trung tâm. Quản lý trạng thái tường lửa, đồng bộ hóa Luật (Rules) hai chiều (từ Database xuống File `.rules`), và phục vụ các truy vấn từ Frontend.
5.  **SOC Dashboard (Vue.js 3):** Giao diện điều hành (Frontend) được thiết kế theo phong cách Glassmorphism, tối ưu hóa trải nghiệm người dùng (UX) cho các hoạt động giám sát cường độ cao.

---

## 🛠️ Ngăn xếp Công nghệ (Technology Stack)

| Phân lớp | Công nghệ áp dụng | Vai trò |
| :--- | :--- | :--- |
| **Backend / API** | Python 3.11, Flask, PyMySQL | Xử lý logic nghiệp vụ, SOAR, Tương tác OS |
| **Frontend / UI** | Vue.js 3 (Composition), Chart.js | Trực quan hóa dữ liệu, Quản trị Rule |
| **Security Engine**| Snort 3.x, Libdaq, NFQ | Deep Packet Inspection, IPS Engine |
| **Hạ tầng mạng** | Linux Iptables, NetfilterQueue | Định tuyến nội tuyến, Tường lửa hạt nhân |
| **Cơ sở dữ liệu** | MySQL 8.0 Enterprise | Lưu trữ bền vững (Persistent Storage) |
| **DevOps** | Docker, Docker Compose | Đóng gói, Điều phối triển khai (Orchestration)|

---

##  Hướng dẫn Triển khai (Deployment Guide)

Hệ thống được thiết kế để triển khai nhanh chóng thông qua Docker. Vui lòng đọc kỹ các yêu cầu trước khi tiến hành.

### Yêu cầu Tiền đề (Prerequisites)
* **Hệ điều hành:** Khuyến nghị Ubuntu 22.04 LTS (Jammy Jellyfish) hoặc các bản phân phối Linux Kernel 5.4+.
* **Tài nguyên phần cứng (Khuyến nghị):** RAM >= 4GB, CPU >= 2 Cores.
* **Môi trường:** Đã cài đặt `docker` (phiên bản 20.10+) và `docker-compose` (phiên bản v2+).
* **Quyền hạn:** User hiện tại phải có quyền `sudo` (Cần thiết để cấu hình Iptables).

### Quy trình Cài đặt (Step-by-Step)

**Bước 1: Sao chép Mã nguồn**
```bash
git clone [https://github.com/dotuyen2409/bk_ids.git](https://github.com/dotuyen2409/bk_ids.git)
cd bk_ids