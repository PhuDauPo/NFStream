# IoTGuardAI — Tài liệu Kỹ thuật Chi tiết

## 1. Tổng quan hệ thống

IoTGuardAI là hệ thống **Phát hiện Xâm nhập Mạng (IDS)** hai tầng dành cho môi trường IoT, chạy trên Raspberry Pi và kết hợp với AWS IoT Cloud.

### Mô hình Teacher–Student

| | Mô hình Trò (Student) | Mô hình Thầy (Teacher) |
|---|---|---|
| **Vị trí** | Raspberry Pi (Edge) | AWS Cloud |
| **Input** | 15 engineered features | 75 raw NFStream fields |
| **Model** | LightGBM → ONNX | Mô hình mạnh hơn trên cloud |
| **Mục đích** | Phát hiện realtime | Giám sát & xác minh Student |
| **Output** | 0 (Normal) / 1 (Attack) | Phân loại chi tiết hơn |

---

## 2. Kiến trúc tổng thể

```
Raspberry Pi — Docker Container
│
├── [Process 1] app.py        — Flask API, cổng 5000
│       └── ONNX LightGBM model
│
└── [Process 2] collector.py  — Hub thu thập & phân phối
        │
        │  NFStreamer (wlan0, promiscuous, idle_timeout=15s, active_timeout=60s)
        │  Mỗi flow hợp lệ (≥ 3 packets):
        │
        ├── Tạo flow_id duy nhất
        │
        ├── [Thread: SenderLog]
        │       └── 75 raw fields → MQTT "log" → Teacher Model
        │
        └── [Thread: SenderPredict]
                ├── 15 features → POST /predict → app.py
                └── prediction == "1"?
                        └── MQTT "anomaly" → Alert Cloud
```

```
AWS IoT Core
├── topic: "log"      ← mọi flow (75 fields)
└── topic: "anomaly"  ← chỉ flow bị phát hiện tấn công
```

---

## 3. Chi tiết `collector.py`

### 3.1. Cấu hình (Config)

```python
API_URL    = os.getenv("API_URL",    "http://localhost:5000/predict")
INTERFACE  = "wlan0"
CLIENT_ID  = os.getenv("MQTT_CLIENT_ID", "raspi-nfstream")
ENDPOINT   = os.getenv("MQTT_ENDPOINT",  "<aws-endpoint>.iot.ap-southeast-2.amazonaws.com")
CERT_PATH  = os.getenv("CERT_PATH",  "/app/certs/Raspberry-MQTT.cert.pem")
KEY_PATH   = os.getenv("KEY_PATH",   "/app/certs/Raspberry-MQTT.private.key")
CA_PATH    = os.getenv("CA_PATH",    "/app/certs/root-CA.crt")
TOPIC_LOG  = "log"
TOPIC_ANOM = "anomaly"
MIN_BIDIRECTIONAL_PACKETS = 3
```

Tất cả cấu hình nhạy cảm đều đọc từ **environment variables** — không hardcode trong image.

---

### 3.2. Flow ID — Khóa chính định danh mỗi flow

```python
now     = datetime.now()
flow_id = (
    f"{CLIENT_ID}"
    f"_{now.strftime('%Y%m%d_%H%M%S')}"
    f"_{now.microsecond:06d}"
    f"_{next(_flow_counter):05d}"   # counter tăng dần, thread-safe
)
```

**Ví dụ:** `raspi-nfstream_20260414_214255_847291_00042`

| Phần | Ý nghĩa |
|---|---|
| `raspi-nfstream` | Tên thiết bị (`MQTT_CLIENT_ID`) |
| `20260414` | Ngày (YYYYMMDD) |
| `214255` | Giờ:phút:giây (HHMMSS) |
| `847291` | Microseconds (6 chữ số) |
| `00042` | Counter tăng dần (5 chữ số) |

> **Tại sao an toàn tuyệt đối:** kể cả 2 flow xảy ra cùng microsecond, counter đảm bảo không trùng.

Cùng `flow_id` xuất hiện ở **cả 2 topic** → Cloud dễ dàng match:
```sql
SELECT log.flow FROM log
JOIN anomaly ON log.flow_id = anomaly.flow_id
```

---

### 3.3. Lọc flow (Flow Filter)

```python
MIN_BIDIRECTIONAL_PACKETS = 3

def is_valid_flow(flow) -> bool:
    return safe_get(flow, 'bidirectional_packets') >= MIN_BIDIRECTIONAL_PACKETS
```

Flow có ít hơn 3 packets bị **bỏ qua** — không đủ thông tin thống kê để dự đoán chính xác.

---

### 3.4. 75 Raw Fields (Teacher Model)

Toàn bộ metadata của một network flow từ NFStream, bao gồm:
- **Identity**: `id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- **Timing**: `bidirectional_duration_ms`, `first_seen_ms`, `last_seen_ms`
- **Volume**: `bidirectional_packets`, `bidirectional_bytes`, `src2dst_bytes`, `dst2src_bytes`
- **Packet size stats**: `min_ps`, `mean_ps`, `stddev_ps`, `max_ps` (theo cả 3 hướng)
- **Inter-arrival time stats**: `min_piat_ms`, `mean_piat_ms`, `stddev_piat_ms`, `max_piat_ms`
- **TCP Flags**: `syn`, `ack`, `rst`, `fin`, `psh`, `urg`, `cwr`, `ece` packets (3 hướng)
- **Application**: `application_name`, `application_category_name`, `application_confidence`
- **Deep inspection**: `requested_server_name`, `user_agent`, `client_fingerprint`

---

### 3.5. 15 Engineered Features (Student Model)

| # | Feature | Loại | Công thức / Nguồn |
|---|---|---|---|
| 1 | `src2dst_syn_ratio` | Computed | `src2dst_syn_packets / src2dst_packets` |
| 2 | `bidirectional_syn_ratio` | Computed | `bidir_syn_packets / bidirectional_packets` |
| 3 | `bidirectional_rst_ratio` | Computed | `bidir_rst_packets / bidirectional_packets` |
| 4 | `application_confidence` | Direct | NFStream trực tiếp |
| 5 | `dst_port_is_well_known` | Computed | `1.0 if dst_port <= 1023 else 0.0` |
| 6 | `dst_port_bucket` | Computed | `0=well-known / 1=registered / 2=ephemeral` |
| 7 | `dst2src_rst_packets` | Direct | NFStream trực tiếp |
| 8 | `protocol` | Direct | NFStream trực tiếp (6=TCP, 17=UDP) |
| 9 | `src2dst_syn_packets` | Direct | NFStream trực tiếp |
| 10 | `application_category_name` | Encoded | Tra bảng `APP_CAT_MAP` → số nguyên |
| 11 | `dst2src_min_ps` | Direct | NFStream trực tiếp |
| 12 | `pkt_per_byte_ratio` | Computed | `bidirectional_packets / bidirectional_bytes` |
| 13 | `dst2src_stddev_ps` | Direct | NFStream trực tiếp |
| 14 | `bidirectional_min_ps` | Direct | NFStream trực tiếp |
| 15 | `bidirectional_syn_packets` | Direct | NFStream trực tiếp |

#### APP_CAT_MAP — Encoding Application Category

| Tên (nDPI) | Số | Tên (nDPI) | Số |
|---|---|---|---|
| Web | 0 | Network | 9 |
| Mail | 1 | System | 10 |
| Streaming | 2 | Database | 11 |
| VoIP | 3 | RemoteAccess | 12 |
| DataTransfer | 4 | Cloud | 13 |
| DownloadFT | 5 | SocialNetwork | 14 |
| Gaming | 6 | Collaborative | 15 |
| Chat | 7 | RPC | 16 |
| VPN | 8 | SwUpdate | 17 |
| | | Unspecified | 18 |

---

### 3.6. Queue Architecture (Non-blocking)

```
capture_thread (main)
    │
    ├── LOG_QUEUE (maxsize=256)
    │       └── SenderLog Thread
    │             • Lấy (flow_id, dict_75) từ queue
    │             • json.dumps với default=str (xử lý bytes/object)
    │             • mqtt.publish → topic "log", QoS AT_LEAST_ONCE
    │
    └── PREDICT_QUEUE (maxsize=256)
            └── SenderPredict Thread
                  • POST /predict, timeout=1s
                  • status 200? → đọc prediction
                  • prediction=="1"? → mqtt.publish → topic "anomaly"
                  • Timeout → sleep 0.5s
                  • ConnectionError → sleep 2s
```

> **Tại sao dùng Queue:** NFStream là realtime, `requests.post()` là blocking. Không dùng Queue → mỗi flow phải chờ API response → drop packets khi traffic cao.

---

## 4. Chi tiết `app.py` (Flask Inference API)

### 4.1. Startup — Load model

```python
MODEL_PATH   = "/app/models/lightgbm_model.onnx"
COLUMNS_PATH = "/app/models/model_columns.joblib"

session      = ort.InferenceSession(MODEL_PATH)     # ONNX Runtime
model_columns = joblib.load(COLUMNS_PATH)            # danh sách cột sau preprocessing
```

### 4.2. Endpoint `/predict` — Pipeline xử lý

```
POST /predict
  Body: {"features": [v1, v2, ..., v15]}
  │
  ├── 1. Tạo DataFrame với original_columns (15 tên)
  │
  ├── 2. pd.get_dummies() — One-Hot Encoding cột dạng object
  │       (application_category_name đã encode số → không ảnh hưởng)
  │
  ├── 3. reindex(columns=model_columns, fill_value=0)
  │       Đảm bảo đúng thứ tự cột như lúc train
  │
  ├── 4. ONNX Runtime inference
  │       input: float32 numpy array
  │       output: [label, probabilities]
  │
  └── 5. Return {"prediction": "0"} hoặc {"prediction": "1"}
```

### 4.3. Endpoint `/health`

```
GET /health → "OK" 200
```
Dùng cho Docker HEALTHCHECK:
```dockerfile
HEALTHCHECK --interval=10s --timeout=5s --start-period=25s --retries=3 \
  CMD curl -fs http://localhost:5000/health || exit 1
```

---

## 5. MQTT Payload Schemas

### Topic: `"log"` — Mọi flow hợp lệ

```json
{
  "flow_id":   "raspi-nfstream_20260414_214255_847291_00042",
  "device_id": "raspi-nfstream",
  "timestamp": 1744123456,
  "flow": {
    "id": 1,
    "src_ip": "192.168.1.5",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": 6,
    "bidirectional_packets": 24,
    "bidirectional_bytes": 8192,
    "bidirectional_syn_packets": 1,
    "application_name": "TLS",
    "application_category_name": "Web",
    "... (75 fields total)": "..."
  }
}
```

### Topic: `"anomaly"` — Chỉ khi detection == Attack

```json
{
  "flow_id":   "raspi-nfstream_20260414_214255_847291_00042",
  "device_id": "raspi-nfstream",
  "timestamp": 1744123456,
  "prediction": 1,
  "src_ip":    "192.168.1.100",
  "dst_ip":    "203.0.113.5",
  "dst_port":  80,
  "features": {
    "src2dst_syn_ratio":       1.0,
    "bidirectional_syn_ratio": 0.5,
    "bidirectional_rst_ratio": 0.0,
    "application_confidence":  0,
    "dst_port_is_well_known":  1.0,
    "dst_port_bucket":         0,
    "dst2src_rst_packets":     0,
    "protocol":                6,
    "src2dst_syn_packets":     4,
    "application_category_name": 0,
    "dst2src_min_ps":          0,
    "pkt_per_byte_ratio":      0.003,
    "dst2src_stddev_ps":       0,
    "bidirectional_min_ps":    60,
    "bidirectional_syn_packets": 4
  }
}
```

> **Cloud matching:** `flow_id` giống nhau ở cả 2 topic → Teacher model lấy 75 fields từ "log" để verify.

---

## 6. Docker & Deployment

### 6.1. Cấu trúc Container

```
/app/
├── src/
│   ├── app.py          — Flask API
│   └── collector.py    — Hub collector
├── models/
│   ├── lightgbm_model.onnx
│   └── model_columns.joblib
└── certs/              ← volume mount từ Pi
    ├── Raspberry-MQTT.cert.pem
    ├── Raspberry-MQTT.private.key
    └── root-CA.crt
```

### 6.2. Process Manager (supervisord)

```ini
[program:app]
command=/opt/conda/envs/appenv/bin/python /app/src/app.py
autostart=true
autorestart=true

[program:collector]
command=/opt/conda/envs/appenv/bin/python /app/src/collector.py
autostart=true
autorestart=true
```

### 6.3. Lệnh cập nhật & chạy đầy đủ trên Pi

```bash
# ============================================
# BƯỚC 1: Dừng & Xóa container cũ
# ============================================
docker stop rpi_model && docker rm rpi_model

# ============================================
# BƯỚC 2: Dọn dẹp system (không bắt buộc)
# ============================================
# docker image prune -a -f

# ============================================
# BƯỚC 3: Pull image mới nhất
# ============================================
docker pull hoangphu20/rpi-model:latest
docker pull containrrr/watchtower:latest

# ============================================
# BƯỚC 4: Chạy lại Watchtower
# ============================================
docker run -d \
  --name watchtower \
  --restart always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower \
  --cleanup \
  --include-restarting \
  --label-enable \
  --interval 300

# ============================================
# BƯỚC 5: Chạy lại rpi_model với cấu hình mới
# ============================================
docker run -d \
  --name rpi_model \
  --restart always \
  --net host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --label=com.centurylinklabs.watchtower.enable=true \
  -v ~/connect_device_package:/app/certs \
  -e CERT_PATH=/app/certs/Raspberry-MQTT.cert.pem \
  -e KEY_PATH=/app/certs/Raspberry-MQTT.private.key \
  -e CA_PATH=/app/certs/root-CA.crt \
  -e MQTT_ENDPOINT=a2sdt01uorkibr-ats.iot.ap-southeast-2.amazonaws.com \
  -e MQTT_CLIENT_ID=raspi-nfstream \
  hoangphu20/rpi-model:latest

# ============================================
# BƯỚC 6: Kiểm tra trạng thái
# ============================================
echo ""
echo "=== CONTAINER STATUS ==="
docker ps -a

echo ""
echo "=== LOG rpi_model (10 dòng đầu) ==="
sleep 3
docker logs --tail 20 rpi_model
```

> Sau mỗi lần `bash deploy_watchtower.sh` từ máy dev → Watchtower tự pull image mới và restart `rpi_model` **giữ nguyên** volume + env vars.

### 6.5. Multi-arch Build (amd64 + arm64)

```bash
# Từ máy Windows (WSL2/Git Bash)
bash deploy_watchtower.sh

# Build cho cả 2 arch:
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t hoangphu20/rpi-model:latest \
  -f docker/Dockerfile \
  --push .
```

---

## 7. Luồng dữ liệu hoàn chỉnh (End-to-End)

```
[Thiết bị IoT trên mạng]
         │ packets
         ▼
[NFStreamer - wlan0, promiscuous]
         │ flow (sau idle_timeout=1s hoặc active_timeout=2s)
         ▼
  is_valid_flow()? (≥3 packets)
         │ YES
         ▼
  Tạo flow_id duy nhất
         │
    ┌────┴────┐
    ▼         ▼
LOG_QUEUE   PREDICT_QUEUE
    │              │
    ▼              ▼
SenderLog   SenderPredict
    │              │
    │         POST /predict
    │              │
    │         app.py (ONNX)
    │              │
    │         prediction?
    │         ┌────┴────┐
    │         │ "0"     │ "1"
    │         ▼         ▼
    │       Normal    ATTACK
    │                   │
    ▼                   ▼
MQTT "log"        MQTT "anomaly"
(75 fields)       (flow_id + 15 features)
    │                   │
    └─────────┬─────────┘
              ▼
        AWS IoT Core
              │
    ┌─────────┴─────────┐
    ▼                   ▼
Teacher Model       Alert System
(verify Student)    (Dashboard/Notify)
```

---

## 8. Kiểm tra hệ thống

```bash
# Xem log realtime
docker logs -f rpi_model

# Output mong đợi:
# 10:00:01 [INFO] ✅ MQTT connected → a2sdt01uorkibr...
# 10:00:01 [INFO] Capture thread started on interface: wlan0
# 10:00:01 [INFO] SenderLog thread started → topic: 'log'
# 10:00:01 [INFO] SenderPredict thread started → http://localhost:5000/predict
# 10:00:03 [INFO] [raspi-nfs] src=192.168.1.5   dst=8.8.8.8    port=443   → ✅ Normal
# 10:00:04 [WARNING] 🚨 ANOMALY [raspi-nfs] sent → MQTT topic 'anomaly'

# Kiểm tra health
curl http://localhost:5000/health
# → OK

# Xem trạng thái container
docker ps -a
```
