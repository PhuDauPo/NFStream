import requests
from nfstream import NFStreamer
import time

API_URL = "http://localhost:5000/predict"   # Flask API trong cùng container

# Danh sách 17 trường mô hình yêu cầu
FIELDS = [
    "dst_port",
    "protocol",
    "bidirectional_duration_ms",
    "src2dst_packets",
    "dst2src_packets",
    "src2dst_bytes",
    "dst2src_bytes",
    "application_name",
    "bidirectional_syn_packets",
    "bidirectional_ack_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
]

def start_collector():
    print("⚡ NFStream Collector started — capturing live flows...\n")

    # NFStream settings — tối ưu realtime
    stream = NFStreamer(
        source="wlan0",               # đổi thành eth0 nếu chạy bridge mode
        decode_tunnels=True,
        promiscuous_mode=True,
        statistical_analysis=True,    # bắt buộc để tính toán mean/std
        idle_timeout=1,
        active_timeout=2,
    )

    for flow in stream:
        try:
            # Lấy 17 trường từ NFStream
            feats = [getattr(flow, k, 0) for k in FIELDS]
            data = {"features": feats}

            # Gửi sang mô hình ONNX
            response = requests.post(API_URL, json=data, timeout=1)

            print(f"🔍 Features: {data}")
            print(f"🔮 Prediction: {response.json()}\n")

        except Exception as e:
            print(f"❌ Error sending to model: {e}")
            time.sleep(0.2)


if __name__ == "__main__":
    start_collector()
