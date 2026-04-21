import os
import itertools
from datetime import datetime
import json
import time
import logging
import requests
from queue import Queue, Full
from threading import Thread
from nfstream import NFStreamer
from awscrt import mqtt
from awsiot import mqtt_connection_builder

# ─── LOGGING ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Logger riêng cho từng luồng
log_capture = logging.getLogger("CAPTURE")   # Luồng 1: Quét 75 trường
log_predict = logging.getLogger("PREDICT")   # Luồng 2: Kết quả mô hình
log_anomaly = logging.getLogger("ANOMALY")   # Luồng 3: Gửi dữ liệu tấn công

# ─── CONFIG ─────────────────────────────────────────────────
API_URL    = os.getenv("API_URL",    "http://localhost:5000/predict")
INTERFACE  = "wlan0"
CLIENT_ID  = os.getenv("MQTT_CLIENT_ID", "raspi-nfstream")
ENDPOINT   = os.getenv("MQTT_ENDPOINT",  "a2sdt01uorkibr-ats.iot.ap-southeast-2.amazonaws.com")
CERT_PATH  = os.getenv("CERT_PATH",  "/app/certs/Raspberry-MQTT.cert.pem")
KEY_PATH   = os.getenv("KEY_PATH",   "/app/certs/Raspberry-MQTT.private.key")
CA_PATH    = os.getenv("CA_PATH",    "/app/certs/root-CA.crt")
TOPIC_LOG  = "log"
TOPIC_ANOM = "anomaly"

MIN_BIDIRECTIONAL_PACKETS = 3

# ─── APP CATEGORY MAP ────────────────────────────────────────
APP_CAT_MAP = {
    'Web': 0, 'Mail': 1, 'Streaming': 2, 'VoIP': 3,
    'DataTransfer': 4, 'DownloadFT': 5, 'Gaming': 6, 'Chat': 7,
    'VPN': 8, 'Network': 9, 'System': 10, 'Database': 11,
    'RemoteAccess': 12, 'Cloud': 13, 'SocialNetwork': 14,
    'Collaborative': 15, 'RPC': 16, 'SwUpdate': 17, 'Unspecified': 18,
}

# ─── 75 RAW FIELDS (cho Teacher model) ──────────────────────
ALL_FIELDS = [
    "id", "expiration_id", "src_ip", "src_mac", "src_oui", "src_port",
    "dst_ip", "dst_mac", "dst_oui", "dst_port", "protocol", "ip_version",
    "vlan_id", "tunnel_id",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms", "bidirectional_duration_ms",
    "bidirectional_packets", "bidirectional_bytes",
    "src2dst_first_seen_ms", "src2dst_last_seen_ms", "src2dst_duration_ms",
    "src2dst_packets", "src2dst_bytes",
    "dst2src_first_seen_ms", "dst2src_last_seen_ms", "dst2src_duration_ms",
    "dst2src_packets", "dst2src_bytes",
    "bidirectional_min_ps", "bidirectional_mean_ps", "bidirectional_stddev_ps", "bidirectional_max_ps",
    "src2dst_min_ps", "src2dst_mean_ps", "src2dst_stddev_ps", "src2dst_max_ps",
    "dst2src_min_ps", "dst2src_mean_ps", "dst2src_stddev_ps", "dst2src_max_ps",
    "bidirectional_min_piat_ms", "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms", "bidirectional_max_piat_ms",
    "src2dst_min_piat_ms", "src2dst_mean_piat_ms", "src2dst_stddev_piat_ms", "src2dst_max_piat_ms",
    "dst2src_min_piat_ms", "dst2src_mean_piat_ms", "dst2src_stddev_piat_ms", "dst2src_max_piat_ms",
    "bidirectional_syn_packets", "bidirectional_cwr_packets", "bidirectional_ece_packets",
    "bidirectional_urg_packets", "bidirectional_ack_packets", "bidirectional_psh_packets",
    "bidirectional_rst_packets", "bidirectional_fin_packets",
    "src2dst_syn_packets", "src2dst_cwr_packets", "src2dst_ece_packets", "src2dst_urg_packets",
    "src2dst_ack_packets", "src2dst_psh_packets", "src2dst_rst_packets", "src2dst_fin_packets",
    "dst2src_syn_packets", "dst2src_cwr_packets", "dst2src_ece_packets", "dst2src_urg_packets",
    "dst2src_ack_packets", "dst2src_psh_packets", "dst2src_rst_packets", "dst2src_fin_packets",
    "application_name", "application_category_name", "application_is_guessed",
    "application_confidence", "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
]

# ─── 17 FEATURES (cho Student model) ────────────────────────
TOP17_FEATURES = [
    'protocol',                      # 1. Giao thức (TCP/UDP)
    'dst_port',                      # 2. Port đích
    'bidirectional_packets',         # 3. Tổng số packets hai chiều
    'src2dst_packets',               # 4. Số packets từ nguồn đến đích
    'dst2src_packets',               # 5. Số packets từ đích về nguồn
    'bidirectional_bytes',           # 6. Tổng số bytes hai chiều
    'src2dst_bytes',                 # 7. Số bytes từ nguồn đến đích
    'dst2src_bytes',                 # 8. Số bytes từ đích về nguồn
    'bidirectional_mean_ps',         # 9. Trung bình packet size hai chiều
    'bidirectional_stddev_ps',       # 10. Độ lệch chuẩn packet size
    'bidirectional_duration_ms',     # 11. Thời lượng flow (ms)
    'bidirectional_mean_piat_ms',    # 12. Trung bình inter-arrival time
    'bidirectional_max_piat_ms',     # 13. Max inter-arrival time
    'bidirectional_syn_packets',     # 14. Số SYN packets hai chiều
    'bidirectional_rst_packets',     # 15. Số RST packets hai chiều
    'pkt_per_byte_ratio',            # 16. Tỷ lệ packets/bytes
    'flow_symmetry',                 # 17. Độ đối xứng của flow
]

# ─── QUEUES ─────────────────────────────────────────────────
# Counter tăng dần, thread-safe (GIL đảm bảo)
_flow_counter = itertools.count(1)

# item trong LOG_QUEUE     : (flow_id, flow_dict_75)
# item trong PREDICT_QUEUE : (flow_id, feats_17, src_ip, dst_ip, dst_port)
LOG_QUEUE     = Queue(maxsize=256)
PREDICT_QUEUE = Queue(maxsize=256)


# ─── MQTT SETUP ─────────────────────────────────────────────

def init_mqtt():
    """Khởi tạo MQTT connection tới AWS IoT Core."""
    try:
        conn = mqtt_connection_builder.mtls_from_path(
            endpoint=ENDPOINT,
            cert_filepath=CERT_PATH,
            pri_key_filepath=KEY_PATH,
            ca_filepath=CA_PATH,
            client_id=CLIENT_ID,
            clean_session=True,
            keep_alive_secs=30,
        )
        conn.connect().result()
        log.info("✅ MQTT connected → %s", ENDPOINT)
        return conn
    except Exception as e:
        log.error("❌ MQTT connection failed: %s", e)
        return None


# ─── HELPERS ────────────────────────────────────────────────

def safe_get(flow, field, default=0):
    val = getattr(flow, field, None)
    return val if val is not None else default


def is_valid_flow(flow) -> bool:
    return safe_get(flow, 'bidirectional_packets') >= MIN_BIDIRECTIONAL_PACKETS


def extract_all_fields(flow) -> dict:
    """Trích xuất 75 raw fields cho Teacher model."""
    return {f: getattr(flow, f, None) for f in ALL_FIELDS}


def extract_features(flow) -> list:
    """Trích xuất 17 features cho Student model."""
    # Lấy các giá trị cơ bản từ flow
    protocol              = safe_get(flow, 'protocol')
    dst_port              = safe_get(flow, 'dst_port')
    bidirectional_packets = safe_get(flow, 'bidirectional_packets')
    src2dst_packets       = safe_get(flow, 'src2dst_packets')
    dst2src_packets       = safe_get(flow, 'dst2src_packets')
    bidirectional_bytes   = safe_get(flow, 'bidirectional_bytes')
    src2dst_bytes         = safe_get(flow, 'src2dst_bytes')
    dst2src_bytes         = safe_get(flow, 'dst2src_bytes')
    
    # Tính toán các features phái sinh
    pkt_per_byte_ratio = bidirectional_packets / bidirectional_bytes if bidirectional_bytes > 0 else 0.0
    
    # flow_symmetry: Độ đối xứng giữa src→dst và dst→src
    # Công thức: min(src2dst_bytes, dst2src_bytes) / max(src2dst_bytes, dst2src_bytes)
    max_bytes = max(src2dst_bytes, dst2src_bytes)
    min_bytes = min(src2dst_bytes, dst2src_bytes)
    flow_symmetry = min_bytes / max_bytes if max_bytes > 0 else 0.0
    
    return [
        protocol,                                    # 1
        dst_port,                                    # 2
        bidirectional_packets,                       # 3
        src2dst_packets,                             # 4
        dst2src_packets,                             # 5
        bidirectional_bytes,                         # 6
        src2dst_bytes,                               # 7
        dst2src_bytes,                               # 8
        safe_get(flow, 'bidirectional_mean_ps'),     # 9
        safe_get(flow, 'bidirectional_stddev_ps'),   # 10
        safe_get(flow, 'bidirectional_duration_ms'), # 11
        safe_get(flow, 'bidirectional_mean_piat_ms'),# 12
        safe_get(flow, 'bidirectional_max_piat_ms'), # 13
        safe_get(flow, 'bidirectional_syn_packets'), # 14
        safe_get(flow, 'bidirectional_rst_packets'), # 15
        pkt_per_byte_ratio,                          # 16
        flow_symmetry,                               # 17
    ]


# ─── THREAD 1: SENDER LOG (75 fields → MQTT "log") ──────────

def sender_log_thread(mqtt_conn):
    log.info("SenderLog thread started → topic: '%s'", TOPIC_LOG)
    while True:
        flow_id, flow_dict = LOG_QUEUE.get()
        if mqtt_conn:
            try:
                # Log thông tin 75 trường đã quét
                log_capture.info("📊 [%s] Captured 75 fields → src=%s dst=%s port=%s proto=%s packets=%s",
                                flow_id[:12],
                                flow_dict.get('src_ip', 'N/A'),
                                flow_dict.get('dst_ip', 'N/A'),
                                flow_dict.get('dst_port', 'N/A'),
                                flow_dict.get('protocol', 'N/A'),
                                flow_dict.get('bidirectional_packets', 'N/A'))
                
                payload = json.dumps({
                    "flow_id":   flow_id,          # ← khóa chính để match với anomaly
                    "device_id": CLIENT_ID,
                    "timestamp": int(time.time()),
                    "flow":      flow_dict,
                }, default=str)
                mqtt_conn.publish(
                    topic=TOPIC_LOG,
                    payload=payload,
                    qos=mqtt.QoS.AT_LEAST_ONCE,
                )
            except Exception as e:
                log.error("MQTT log publish error: %s", e)
        LOG_QUEUE.task_done()


# ─── THREAD 2: SENDER PREDICT (17 features → /predict → anomaly) ──

def sender_predict_thread(mqtt_conn):
    log.info("SenderPredict thread started → %s", API_URL)
    while True:
        flow_id, feats, src_ip, dst_ip, dst_port = PREDICT_QUEUE.get()
        try:
            response = requests.post(API_URL, json={"features": feats}, timeout=3)

            if response.status_code == 200:
                raw_pred = response.json().get("prediction", "0")
                prediction = str(raw_pred)

                # Log kết quả prediction từ mô hình
                if prediction == "1":
                    log_predict.warning("🔴 [%s] ATTACK DETECTED → src=%s dst=%s port=%s",
                                       flow_id[:12], src_ip, dst_ip, dst_port)
                else:
                    log_predict.info("🟢 [%s] Normal Traffic → src=%s dst=%s port=%s",
                                    flow_id[:12], src_ip, dst_ip, dst_port)

                # Gửi MQTT "anomaly" nếu Student model phát hiện tấn công
                if prediction == "1" and mqtt_conn:
                    anomaly_payload = json.dumps({
                        "flow_id":   flow_id,      # ← cùng flow_id với "log" → cloud match được
                        "device_id": CLIENT_ID,
                        "timestamp": int(time.time()),
                        "prediction": 1,
                        "src_ip":   src_ip,
                        "dst_ip":   dst_ip,
                        "dst_port": dst_port,
                        "features": dict(zip(TOP17_FEATURES, feats)),
                    })
                    mqtt_conn.publish(
                        topic=TOPIC_ANOM,
                        payload=anomaly_payload,
                        qos=mqtt.QoS.AT_LEAST_ONCE,
                    )
                    # Log thông tin đã gửi anomaly
                    log_anomaly.critical("🚨 [%s] ANOMALY SENT to MQTT → topic='%s' src=%s dst=%s port=%s",
                                        flow_id[:12], TOPIC_ANOM, src_ip, dst_ip, dst_port)
            else:
                log.warning("API HTTP %s: %s", response.status_code, response.text[:100])

        except requests.exceptions.Timeout:
            log.warning("API timeout.")
            time.sleep(0.5)
        except requests.exceptions.ConnectionError:
            log.error("Cannot connect to API. Retry in 2s...")
            time.sleep(2)
        except Exception as e:
            log.error("Predict error: %s", e)
            time.sleep(0.2)
        finally:
            PREDICT_QUEUE.task_done()


# ─── CAPTURE (Main thread) ───────────────────────────────────

def capture_thread():
    log.info("Capture thread started on interface: %s", INTERFACE)
    stream = NFStreamer(
        source=INTERFACE,
        decode_tunnels=True,
        promiscuous_mode=True,
        statistical_analysis=True,
        idle_timeout=15,   # tăng từ 1s → 15s: tránh flow bị cắt sớm → SYN ratio cao giả
        active_timeout=60, # tăng từ 2s → 60s: cho phép flow dài hoàn chỉnh
    )
    for flow in stream:
        if not is_valid_flow(flow):
            continue

        # flow_id: {device}_{YYYYMMDD}_{HHMMSS}_{microseconds}_{counter}
        # Counter tăng dần đảm bảo tuyệt đối không trùng dù 2 flow xảy ra cùng microsecond
        # Ví dụ: raspi-nfstream_20260414_214255_847291_00042
        now     = datetime.now()
        flow_id = (
            f"{CLIENT_ID}"
            f"_{now.strftime('%Y%m%d_%H%M%S')}"
            f"_{now.microsecond:06d}"
            f"_{next(_flow_counter):05d}"
        )
        src_ip   = getattr(flow, 'src_ip', '')
        dst_ip   = getattr(flow, 'dst_ip', '')
        dst_port = safe_get(flow, 'dst_port')

        # Đẩy vào LOG_QUEUE (flow_id + 75 fields)
        try:
            LOG_QUEUE.put_nowait((flow_id, extract_all_fields(flow)))
        except Full:
            log.warning("LOG_QUEUE full — dropping flow.")

        # Đẩy vào PREDICT_QUEUE (flow_id + 17 features)
        try:
            PREDICT_QUEUE.put_nowait((flow_id, extract_features(flow), src_ip, dst_ip, dst_port))
        except Full:
            log.warning("PREDICT_QUEUE full — dropping flow.")


# ─── ENTRY POINT ────────────────────────────────────────────

def start_collector():
    log.info("⚡ IoTGuardAI Collector starting...")

    mqtt_conn = init_mqtt()

    # Khởi động 2 worker threads
    Thread(target=sender_log_thread,     args=(mqtt_conn,), daemon=True, name="SenderLog").start()
    Thread(target=sender_predict_thread, args=(mqtt_conn,), daemon=True, name="SenderPredict").start()

    capture_thread()   # chạy ở main thread


if __name__ == "__main__":
    start_collector()
