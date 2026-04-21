# src/app.py

from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import onnxruntime as ort
import joblib
import logging
import sys
import os

# --- INITIALIZATION ---
app = Flask(__name__)

logging.getLogger('werkzeug').disabled = True
sys.stdout.reconfigure(line_buffering=True)


# --- LOAD MODEL AND ARTIFACTS ---
MODEL_PATH = "/app/models/student_lgbm.onnx"
COLUMNS_PATH = "/app/models/student_lgbm.joblib"

try:
    session = ort.InferenceSession(MODEL_PATH)
    input_name = session.get_inputs()[0].name
    model_columns = joblib.load(COLUMNS_PATH)

    output_name = session.get_outputs()[0].name
    output_info = session.get_outputs()[1].name

    print(f"[OK] Successfully loaded ONNX model from '{MODEL_PATH}'")
    print(f"[INFO] Model input features: {session.get_inputs()[0].shape}")
    print(f"[INFO] Model expects {len(model_columns)} input features.")

except Exception as e:
    print(f"[ERROR] Could not load ONNX model or column file: {e}", flush=True)
    session = None
    model_columns = None



original_columns = [
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

# --- API ENDPOINT ---
@app.route('/predict', methods=['POST'])
def predict():
    if session is None or model_columns is None:
        return jsonify({"error": "Model is not available. Please check server logs."}), 500

    try:
        # 1. GET INPUT DATA
        json_data = request.get_json()
        features = json_data['features']

        # DEBUG: in giá trị các feature đầu vào
        feat_named = dict(zip(original_columns, features))
        print(f"[DEBUG] features in: {feat_named}", flush=True)

        # 2. CREATE DATAFRAME
        input_df = pd.DataFrame([features], columns=original_columns)

        # 3. PREPROCESS INPUT DATA (giống app1.py)
        processed_df = pd.get_dummies(input_df)
        final_df = processed_df.reindex(columns=model_columns, fill_value=0)

        # 4. MAKE PREDICTION USING ONNX RUNTIME
        input_feed = {input_name: final_df.to_numpy().astype(np.float32)}
        raw_outputs = session.run(None, input_feed)
        raw_result  = raw_outputs[0][0]

        # DEBUG: in rõ kiểu trả về của model → giúp phát hiện model trả str hay int
        print(f"[DEBUG] ONNX raw_result = {raw_result!r}  |  type = {type(raw_result).__name__},  "
              f"all_outputs shapes = {[o.shape if hasattr(o,'shape') else type(o) for o in raw_outputs]}",
              flush=True)

        # Ép kiểu để JSON hóa an toàn
        if isinstance(raw_result, (np.generic, np.ndarray)):
            prediction_label = str(raw_result.item())  # chuyển sang Python str/int/float
        else:
            prediction_label = str(raw_result)

        print(f"[DEBUG] prediction_label = '{prediction_label}'", flush=True)

        return jsonify({'prediction': prediction_label})

    except Exception as e:
        print(f"[ERROR] An error occurred during prediction: {e}", flush=True)
        return jsonify({"error": f"Processing error: {str(e)}"}), 400

@app.route("/health")
def health():
    return "OK", 200

# --- RUN THE APP ---
if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000, debug=False)

