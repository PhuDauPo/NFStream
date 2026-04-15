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

# ─── 15 FEATURES (cho Student model) ────────────────────────
TOP15_FEATURES = [
    'src2dst_syn_ratio', 'bidirectional_syn_ratio', 'bidirectional_rst_ratio',
    'application_confidence', 'dst_port_is_well_known', 'dst_port_bucket',
    'dst2src_rst_packets', 'protocol', 'src2dst_syn_packets',
    'application_category_name', 'dst2src_min_ps', 'pkt_per_byte_ratio',
    'dst2src_stddev_ps', 'bidirectional_min_ps', 'bidirectional_syn_packets',
]

# ─── QUEUES ─────────────────────────────────────────────────
# Counter tăng dần, thread-safe (GIL đảm bảo)
_flow_counter = itertools.count(1)

# item trong LOG_QUEUE     : (flow_id, flow_dict_75)
# item trong PREDICT_QUEUE : (flow_id, feats_15, src_ip, dst_ip, dst_port)
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
    """Trích xuất 15 features cho Student model."""
    dst_port              = safe_get(flow, 'dst_port')
    src2dst_packets       = safe_get(flow, 'src2dst_packets')
    bidirectional_packets = safe_get(flow, 'bidirectional_packets')
    bidirectional_bytes   = safe_get(flow, 'bidirectional_bytes')
    src2dst_syn_packets   = safe_get(flow, 'src2dst_syn_packets')
    bidir_syn_packets     = safe_get(flow, 'bidirectional_syn_packets')
    bidir_rst_packets     = safe_get(flow, 'bidirectional_rst_packets')

    src2dst_syn_ratio  = src2dst_syn_packets / src2dst_packets       if src2dst_packets > 0       else 0.0
    bidir_syn_ratio    = bidir_syn_packets   / bidirectional_packets if bidirectional_packets > 0 else 0.0
    bidir_rst_ratio    = bidir_rst_packets   / bidirectional_packets if bidirectional_packets > 0 else 0.0
    pkt_per_byte_ratio = bidirectional_packets / bidirectional_bytes  if bidirectional_bytes > 0  else 0.0

    dst_port_is_well_known = 1.0 if dst_port <= 1023 else 0.0
    dst_port_bucket = 0 if dst_port <= 1023 else (1 if dst_port <= 49151 else 2)

    cat_name = safe_get(flow, 'application_category_name', 'Unspecified') or 'Unspecified'
    if cat_name not in APP_CAT_MAP:
        log.warning("Unknown nDPI category: '%s'", cat_name)
    cat_encoded = APP_CAT_MAP.get(cat_name, APP_CAT_MAP['Unspecified'])

    return [
        src2dst_syn_ratio, bidir_syn_ratio, bidir_rst_ratio,
        safe_get(flow, 'application_confidence'),
        dst_port_is_well_known, dst_port_bucket,
        safe_get(flow, 'dst2src_rst_packets'),
        safe_get(flow, 'protocol'),
        src2dst_syn_packets,
        cat_encoded,
        safe_get(flow, 'dst2src_min_ps'),
        pkt_per_byte_ratio,
        safe_get(flow, 'dst2src_stddev_ps'),
        safe_get(flow, 'bidirectional_min_ps'),
        bidir_syn_packets,
    ]


# ─── THREAD 1: SENDER LOG (75 fields → MQTT "log") ──────────

def sender_log_thread(mqtt_conn):
    log.info("SenderLog thread started → topic: '%s'", TOPIC_LOG)
    while True:
        flow_id, flow_dict = LOG_QUEUE.get()
        if mqtt_conn:
            try:
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


# ─── THREAD 2: SENDER PREDICT (15 features → /predict → anomaly) ──

def sender_predict_thread(mqtt_conn):
    log.info("SenderPredict thread started → %s", API_URL)
    while True:
        flow_id, feats, src_ip, dst_ip, dst_port = PREDICT_QUEUE.get()
        try:
            response = requests.post(API_URL, json={"features": feats}, timeout=3)

            if response.status_code == 200:
                raw_pred = response.json().get("prediction", "0")
                prediction = str(raw_pred)

                # --- DEBUG: log giá trị feature + prediction thực ---
                feat_debug = dict(zip(TOP15_FEATURES, feats))
                log.debug("[%s] features: %s", flow_id[:8], feat_debug)
                log.debug("[%s] raw prediction from model: '%s' (type: %s)",
                          flow_id[:8], prediction, type(raw_pred).__name__)
                # ------------------------------------------------------

                log.info("[%s] src=%-15s dst=%-15s port=%-5s → %s (prediction=%r)",
                         flow_id[:8],
                         src_ip, dst_ip, dst_port,
                         "⚠️  ATTACK" if prediction == "1" else "✅ Normal",
                         prediction)

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
                        "features": dict(zip(TOP15_FEATURES, feats)),
                    })
                    mqtt_conn.publish(
                        topic=TOPIC_ANOM,
                        payload=anomaly_payload,
                        qos=mqtt.QoS.AT_LEAST_ONCE,
                    )
                    log.warning("🚨 ANOMALY [%s] sent → MQTT topic '%s'", flow_id[:8], TOPIC_ANOM)
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

        # Đẩy vào PREDICT_QUEUE (flow_id + 15 features)
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
