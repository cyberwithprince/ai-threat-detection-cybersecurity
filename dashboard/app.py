import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from flask import Flask, render_template, jsonify, send_from_directory, stream_with_context, Response
import os
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import threading
import random
import time
import joblib
from xai.shap_explainer import explain_packet  # Add at top with other imports

# Constants and paths
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "model"))
BINARY_MODEL_PATH = os.path.join(MODEL_PATH, "xgboost_classifier.pkl")
ATTACK_CAT_MODEL_PATH = os.path.join(MODEL_PATH, "xgboost_attack_cat.pkl")
SCALER_PATH = os.path.join(MODEL_PATH, "scaler.pkl")
ENCODER_PATH = os.path.join(MODEL_PATH, "attack_cat_encoder.pkl")
ACTION_LOG_PATH = "../logs/actions_log.csv"
EXPLANATION_PATH = "../logs/explanations"

FEATURE_NAMES = [
    'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack',
    'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src',
    'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
    'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

# Initialize Flask app
app = Flask(__name__)

# Load models and preprocessors
binary_model = joblib.load(BINARY_MODEL_PATH)
attack_cat_model = joblib.load(ATTACK_CAT_MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
attack_cat_encoder = joblib.load(ENCODER_PATH)

# Global variables
packet_data = []
packet_data_store = {}  # New dictionary to store packet features by ID
simulation_running = False
simulation_thread = None

# Helper Functions
def read_action_log():
    """Read and return the action log file as a DataFrame"""
    if os.path.exists(ACTION_LOG_PATH):
        return pd.read_csv(ACTION_LOG_PATH)
    return pd.DataFrame(columns=["timestamp", "ip", "action", "packet_id"])

def extract_packet_features(pkt):
    """Extract features from a network packet"""
    try:
        if IP in pkt:
            proto = pkt[IP].proto
            packet_features = {
                "proto": proto,
                "service": "-",  # Default value if service can't be determined
                "state": "INT",  # Default state
                "spkts": 1,      # Single packet
                "dpkts": 0,
                "sbytes": len(pkt),
                "dbytes": 0,
                "rate": 0,
                "sttl": pkt[IP].ttl,
                "dttl": 0,
                "sload": 0,
                "dload": 0,
                "sloss": 0,
                "dloss": 0,
                "sinpkt": 0,
                "dinpkt": 0,
                "sjit": 0,
                "djit": 0,
                "swin": 0,
                "stcpb": 0,
                "dtcpb": 0,
                "dwin": 0,
                "tcprtt": 0,
                "synack": 0,
                "ackdat": 0,
                "smean": len(pkt),
                "dmean": 0,
                "trans_depth": 0,
                "response_body_len": 0,
                "ct_srv_src": 0,
                "ct_state_ttl": 0,
                "ct_dst_ltm": 0,
                "ct_src_dport_ltm": 0,
                "ct_dst_sport_ltm": 0,
                "ct_dst_src_ltm": 0,
                "is_ftp_login": 0,
                "ct_ftp_cmd": 0,
                "ct_flw_http_mthd": 0,
                "ct_src_ltm": 0,
                "ct_srv_dst": 0,
                "is_sm_ips_ports": 0
            }
            src_ip = pkt[IP].src
            return packet_features, src_ip
    except Exception as e:
        print(f"Packet error: {e}")
    return None, None

def start_simulation():
    """Start the packet capture simulation"""
    global simulation_running, simulation_thread
    if not simulation_running:
        simulation_running = True
        simulation_thread = threading.Thread(target=packet_capture)
        simulation_thread.daemon = True
        simulation_thread.start()
        return True
    return False

def stop_simulation():
    """Stop the packet capture simulation"""
    global simulation_running, simulation_thread
    if simulation_running:
        simulation_running = False
        if simulation_thread:
            simulation_thread.join(timeout=1)
            simulation_thread = None
        return True
    return False

def packet_capture():
    """Capture and process network packets"""
    global packet_data, simulation_running
    while simulation_running:
        try:
            pkt = sniff(count=1, timeout=1)  # Added timeout for graceful stopping
            if not pkt:  # No packet captured
                continue
            features, ip = extract_packet_features(pkt[0])
            if features:
                df = pd.DataFrame([features])
                df.fillna(0, inplace=True)
                scaled_features = scaler.transform(df)
                
                is_attack = binary_model.predict(scaled_features)[0]
                
                attack_category = "N/A"
                if is_attack == 1:
                    attack_cat_pred = attack_cat_model.predict(scaled_features)[0]
                    attack_category = attack_cat_encoder.inverse_transform([attack_cat_pred])[0]
                
                packet_id = int(time.time())
                label = "attack" if is_attack == 1 else "benign"
                
                packet_data.append(f"data: {label},{ip},{attack_category},{packet_id}\n\n")
                packet_data_store[packet_id] = features  # Store packet features by ID
        except Exception as e:
            print(f"Capture error: {e}")
            if not simulation_running:
                break

def start_packet_thread():
    """Start the packet capture thread"""
    capture_thread = threading.Thread(target=packet_capture)
    capture_thread.daemon = True
    capture_thread.start()

# Add these new routes before the main entry point
@app.route("/api/simulation/start", methods=["POST"])
def start_simulation_api():
    """API endpoint to start the simulation"""
    if start_simulation():
        return jsonify({"status": "success", "message": "Simulation started"})
    return jsonify({"status": "error", "message": "Simulation already running"}), 400

@app.route("/api/simulation/stop", methods=["POST"])
def stop_simulation_api():
    """API endpoint to stop the simulation"""
    if stop_simulation():
        return jsonify({"status": "success", "message": "Simulation stopped"})
    return jsonify({"status": "error", "message": "Simulation not running"}), 400

@app.route("/api/simulation/status")
def simulation_status():
    """API endpoint to get simulation status"""
    return jsonify({
        "status": "running" if simulation_running else "stopped",
        "packet_count": len(packet_data)
    })

@app.route("/api/explanation/<packet_id>")
def get_explanation(packet_id):
    """Get SHAP explanation for a packet"""
    try:
        # Get packet features from stored data
        packet_features = packet_data_store.get(packet_id)
        if not packet_features:
            return jsonify({"error": "Packet not found"}), 404
            
        # Create DataFrame with features
        df = pd.DataFrame([packet_features])
        
        # Ensure all features are present and in correct order
        for feature in FEATURE_NAMES:
            if feature not in df.columns:
                df[feature] = 0
        df = df[FEATURE_NAMES]  # Reorder columns
        
        # Scale features
        scaled_features = scaler.transform(df)
        df_scaled = pd.DataFrame(scaled_features, columns=FEATURE_NAMES)
        
        # Generate SHAP explanation
        try:
            explanation_path = explain_packet(df_scaled, packet_id)
            if explanation_path:
                return jsonify({
                    "status": "success",
                    "image_url": f"/explanation_image/{packet_id}_shap.png"
                })
        except Exception as e:
            print(f"SHAP explanation error: {str(e)}")
            return jsonify({"error": "Failed to generate SHAP explanation"}), 500
            
        return jsonify({"error": "Failed to generate explanation"}), 500
        
    except Exception as e:
        print(f"Route error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/explanation_image/<filename>")
def serve_explanation(filename):
    """Serve SHAP explanation images"""
    try:
        explanations_dir = Path(__file__).parent.parent / 'logs' / 'explanations'
        return send_from_directory(str(explanations_dir), filename)
    except Exception as e:
        print(f"Error serving explanation image: {str(e)}")
        return "Image not found", 404

@app.route("/live_stream")
def live_stream():
    """Stream simulated network traffic data"""
    def generate():
        global simulation_running, packet_data_store
        while True:
            if not simulation_running:
                yield "data: keepalive\n\n"
                time.sleep(1)
                continue
                
            # Generate simulated packet data
            packet_type = random.choice(["benign", "attack"])
            ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            attack_category = "N/A"
            
            if packet_type == "attack":
                attack_category = random.choice([
                    "DoS", "DDoS", "Brute Force", 
                    "SQL Injection", "Port Scanning"
                ])
            
            packet_id = str(int(time.time() * 1000))
            
            # Generate simulated features
            features = {
                'proto': random.randint(0, 255),
                'service': random.choice(['http', 'ftp', 'smtp', 'ssh']),
                'state': random.choice(['INT', 'CON', 'FIN']),
                'spkts': random.randint(1, 100),
                'dpkts': random.randint(1, 100),
                'sbytes': random.randint(64, 1500),
                'dbytes': random.randint(64, 1500),
                'rate': random.uniform(0, 100),
                'sttl': random.randint(1, 255),
                'dttl': random.randint(1, 255),
                'sload': random.uniform(0, 1),
                'dload': random.uniform(0, 1),
                'sloss': random.randint(0, 10),
                'dloss': random.randint(0, 10),
                'sinpkt': random.uniform(0, 1),
                'dinpkt': random.uniform(0, 1),
                'sjit': random.uniform(0, 1),
                'djit': random.uniform(0, 1),
                'swin': random.randint(1024, 65535),
                'stcpb': random.randint(0, 1000000),
                'dtcpb': random.randint(0, 1000000),
                'dwin': random.randint(1024, 65535),
                'tcprtt': random.uniform(0, 1),
                'synack': random.uniform(0, 1),
                'ackdat': random.uniform(0, 1),
                'smean': random.uniform(0, 1000),
                'dmean': random.uniform(0, 1000),
                'trans_depth': random.randint(0, 10),
                'response_body_len': random.randint(0, 1000),
                'ct_srv_src': random.randint(0, 100),
                'ct_state_ttl': random.randint(0, 100),
                'ct_dst_ltm': random.randint(0, 100),
                'ct_src_dport_ltm': random.randint(0, 100),
                'ct_dst_sport_ltm': random.randint(0, 100),
                'ct_dst_src_ltm': random.randint(0, 100),
                'is_ftp_login': random.randint(0, 1),
                'ct_ftp_cmd': random.randint(0, 10),
                'ct_flw_http_mthd': random.randint(0, 10),
                'ct_src_ltm': random.randint(0, 100),
                'ct_srv_dst': random.randint(0, 100),
                'is_sm_ips_ports': random.randint(0, 1)
            }
            
            # Store packet features
            packet_data_store[packet_id] = features
            
            # Format: type,ip,category,id
            data = f"data: {packet_type},{ip},{attack_category},{packet_id}\n\n"
            yield data
            time.sleep(1)
            
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream'
    )

# Add after the imports but before other routes
@app.route("/")
def index():
    """Render the main dashboard page"""
    return render_template(
        "index.html",
        total_attacks=len([p for p in packet_data if "attack" in p]),
        total_benign=len([p for p in packet_data if "benign" in p])
    )

# Add this function after other helper functions
def generate_sql_injection_features():
    """Generate features typical of SQL injection attacks"""
    features = {
        'dur': random.uniform(0.1, 2.0),  # Short duration typical of automated attacks
        'proto': 6,  # TCP protocol
        'service': 'http',
        'state': 'CON',
        'spkts': random.randint(3, 10),  # Few packets
        'dpkts': random.randint(2, 8),
        'sbytes': random.randint(800, 2000),  # Large request size
        'dbytes': random.randint(200, 1000),
        'rate': random.uniform(10, 50),  # High rate
        'sttl': 64,
        'dttl': 128,
        'sload': random.uniform(0.5, 1.0),  # High load
        'dload': random.uniform(0.3, 0.8),
        'sloss': 0,
        'dloss': 0,
        'sinpkt': random.uniform(0.8, 1.0),  # High packet rate
        'dinpkt': random.uniform(0.6, 0.9),
        'sjit': random.uniform(0, 0.1),  # Low jitter
        'djit': random.uniform(0, 0.1),
        'swin': 65535,  # Maximum window size
        'stcpb': random.randint(1000000, 2000000),
        'dtcpb': random.randint(500000, 1000000),
        'dwin': 65535,
        'tcprtt': random.uniform(0, 0.1),  # Low RTT
        'synack': random.uniform(0, 0.1),
        'ackdat': random.uniform(0, 0.1),
        'smean': random.uniform(800, 1200),  # Large mean size
        'dmean': random.uniform(200, 500),
        'trans_depth': random.randint(1, 3),
        'response_body_len': random.randint(500, 2000),
        'ct_srv_src': random.randint(10, 50),  # High connection count
        'ct_state_ttl': random.randint(5, 15),
        'ct_dst_ltm': random.randint(10, 30),
        'ct_src_dport_ltm': random.randint(20, 40),  # Multiple ports
        'ct_dst_sport_ltm': random.randint(15, 35),
        'ct_dst_src_ltm': random.randint(10, 25),
        'is_ftp_login': 0,
        'ct_ftp_cmd': 0,
        'ct_flw_http_mthd': random.randint(5, 15),  # Multiple HTTP methods
        'ct_src_ltm': random.randint(20, 40),
        'ct_srv_dst': random.randint(15, 30),
        'is_sm_ips_ports': 1  # Same IP, different ports
    }
    return features

# Main entry point
if __name__ == "__main__":
    app.run(debug=True)