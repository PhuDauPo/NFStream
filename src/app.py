# src/app.py

from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import onnxruntime as ort
import logging
import sys
import os

# --- INITIALIZATION ---
app = Flask(__name__)

logging.getLogger('werkzeug').disabled = True
sys.stdout.reconfigure(line_buffering=True)


# --- LOAD MODEL AND ARTIFACTS ---
MODEL_PATH = "/app/models/student_lgbm.onnx"

try:
    session = ort.InferenceSession(MODEL_PATH)
    input_name = session.get_inputs()[0].name

    output_name = session.get_outputs()[0].name
    output_info = session.get_outputs()[1].name

    print(f"[OK] Successfully loaded ONNX model from '{MODEL_PATH}'")
    print(f"[INFO] Model input features: {session.get_inputs()[0].shape}")

except Exception as e:
    print(f"[ERROR] Could not load ONNX model: {e}", flush=True)
    session = None



original_columns = [
    'src2dst_syn_ratio',          # syn_packets / src2dst_packets
    'bidirectional_syn_ratio',    # syn_packets / bidirectional_packets
    'bidirectional_rst_ratio',    # rst_packets / bidirectional_packets
    'application_confidence',     # từ NFStream trực tiếp
    'dst_port_is_well_known',     # dst_port <= 1023 → 1.0
    'dst_port_bucket',            # 0=well-known, 1=registered, 2=ephemeral
    'dst2src_rst_packets',        # từ NFStream trực tiếp
    'protocol',                   # từ NFStream trực tiếp
    'src2dst_syn_packets',        # từ NFStream trực tiếp
    'application_category_name',  # encoded theo APP_CAT_MAP
    'dst2src_min_ps',             # từ NFStream trực tiếp
    'pkt_per_byte_ratio',         # bidirectional_packets / bidirectional_bytes
    'dst2src_stddev_ps',          # từ NFStream trực tiếp
    'bidirectional_min_ps',       # từ NFStream trực tiếp
    'bidirectional_syn_packets',  # từ NFStream trực tiếp
]

# --- API ENDPOINT ---
@app.route('/predict', methods=['POST'])
def predict():
    if session is None:
        return jsonify({"error": "Model is not available. Please check server logs."}), 500

    try:
        # 1. GET INPUT DATA
        json_data = request.get_json()
        features = json_data['features']

        # DEBUG: in giá trị các feature đầu vào
        feat_named = dict(zip(original_columns, features))
        print(f"[DEBUG] features in: {feat_named}", flush=True)

        # 2. CREATE DATAFRAME & PREPROCESS
        final_df = pd.DataFrame([features], columns=original_columns)

        # 3. MAKE PREDICTION USING ONNX RUNTIME
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

