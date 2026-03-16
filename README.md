# NFStream Traffic Collector

Module này dùng **NFStream** để thu thập **network flow realtime** từ interface mạng và gửi các đặc trưng (features) sang **Flask API** để dự đoán bằng mô hình Machine Learning (ONNX).

Collector sẽ:

1. Capture traffic từ interface mạng.
2. Trích xuất **17 đặc trưng flow**.
3. Gửi dữ liệu đến API `/predict`.
4. Nhận kết quả dự đoán (normal / attack).

---

# Kiến trúc hoạt động

```
Network Traffic
       │
       ▼
   NFStream
       │
       ▼
 Feature Extraction (17 features)
       │
       ▼
 HTTP POST
       │
       ▼
 Flask API (/predict)
       │
       ▼
  ONNX Model
       │
       ▼
 Prediction Result
```

---

# Yêu cầu hệ thống

Python >= 3.9

Cài các thư viện cần thiết:

```bash
pip install nfstream requests
```

Nếu chạy trong Docker cần cấp quyền:

```bash
--net=host
--cap-add=NET_ADMIN
--cap-add=NET_RAW
```

---

# Danh sách Features

Collector trích xuất **17 đặc trưng network flow** từ NFStream.

| Feature                      | Mô tả                             |
| ---------------------------- | --------------------------------- |
| dst_port                     | Cổng đích                         |
| protocol                     | Giao thức (TCP, UDP, etc.)        |
| bidirectional_duration_ms    | Thời gian tồn tại của flow        |
| src2dst_packets              | Số packet từ source → destination |
| dst2src_packets              | Số packet từ destination → source |
| src2dst_bytes                | Số byte từ source → destination   |
| dst2src_bytes                | Số byte từ destination → source   |
| application_name             | Tên ứng dụng                      |
| bidirectional_syn_packets    | Số SYN packet                     |
| bidirectional_ack_packets    | Số ACK packet                     |
| bidirectional_rst_packets    | Số RST packet                     |
| bidirectional_fin_packets    | Số FIN packet                     |
| bidirectional_mean_ps        | Packet size trung bình            |
| bidirectional_stddev_ps      | Độ lệch chuẩn packet size         |
| bidirectional_max_ps         | Packet size lớn nhất              |
| bidirectional_mean_piat_ms   | Mean packet inter-arrival time    |
| bidirectional_stddev_piat_ms | Std packet inter-arrival time     |

---

# Cấu hình Collector

### API endpoint

```python
API_URL = "http://localhost:5000/predict"
```

Đây là endpoint của **Flask inference service**.

---

### Network interface

```python
source="wlan0"
```

Có thể thay đổi tùy môi trường:

| Interface | Mô tả      |
| --------- | ---------- |
| wlan0     | WiFi       |
| eth0      | Ethernet   |
| any       | bắt tất cả |

Ví dụ:

```python
source="eth0"
```

---

# NFStream Settings

Collector được cấu hình để **xử lý realtime**:

```python
NFStreamer(
    source="wlan0",
    decode_tunnels=True,
    promiscuous_mode=True,
    statistical_analysis=True,
    idle_timeout=1,
    active_timeout=2,
)
```

| Parameter            | Ý nghĩa                              |
| -------------------- | ------------------------------------ |
| decode_tunnels       | Phân tích traffic tunnel             |
| promiscuous_mode     | Capture toàn bộ packet               |
| statistical_analysis | Tính toán thống kê flow              |
| idle_timeout         | Flow kết thúc sau 1s không có packet |
| active_timeout       | Update flow sau 2s                   |

---

