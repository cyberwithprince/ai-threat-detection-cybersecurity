from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
import time

# Load the trained XGBoost model
model = joblib.load("../model/xgboost_classifier.pkl")

# Keep track of processed packets
stream_data = []

# Feature extractor
def extract_features(pkt):
    if IP in pkt:
        proto = pkt[IP].proto
        length = len(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        src_port = pkt.sport if TCP in pkt or UDP in pkt else 0
        dst_port = pkt.dport if TCP in pkt or UDP in pkt else 0

        # Build packet dictionary
        features = {
            "srcip": src_ip,
            "dstip": dst_ip,
            "sport": src_port,
            "dsport": dst_port,
            "proto": proto,
            "pktsize": length,
        }

        stream_data.append(features)

        # Predict every 5 packets (for speed)
        if len(stream_data) >= 5:
            run_prediction()

# Predict with model
def run_prediction():
    global stream_data

    df = pd.DataFrame(stream_data)
    df.fillna(0, inplace=True)
    # Drop IPs (not used by model)
    df.drop(["srcip", "dstip"], axis=1, inplace=True)

    preds = model.predict(df)

    for i, pred in enumerate(preds):
        label = "🔒 ATTACK" if pred == 1 else "✅ BENIGN"
        print(f"[{label}] Packet {i+1}: {stream_data[i]}")

        # 🚀 Phase 3 connection: Send (features, pred) to DQN input queue here
        # Example: rl_queue.append((stream_data[i], pred))

    stream_data = []

# Start sniffing
if __name__ == "__main__":
    print("🛰️ Starting real-time prediction loop. Press Ctrl+C to stop.")
    try:
        sniff(prn=extract_features, store=False)
    except KeyboardInterrupt:
        print("\n⏹️ Stopped stream.")
        if stream_data:
            run_prediction()
