import time
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from .dqn_agent import DQNAgent
import joblib
import os

# Make sure directory exists
os.makedirs("../model", exist_ok=True)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = {
    'binary': os.path.join(BASE_DIR, "..", "model", "xgboost_classifier.pkl"),
    'category': os.path.join(BASE_DIR, "..", "model", "xgboost_attack_cat.pkl"),
}
SCALER_PATH = os.path.join(BASE_DIR, "..", "model", "scaler.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "..", "model", "attack_cat_encoder.pkl")
TEST_CSV = os.path.join(BASE_DIR, "..", "data", "UNSW_NB15_testing-set.csv")

# Load trained models and preprocessors
binary_model = joblib.load(MODEL_PATH['binary'])
attack_cat_model = joblib.load(MODEL_PATH['category'])
scaler = joblib.load(SCALER_PATH)
attack_cat_encoder = joblib.load(ENCODER_PATH)

# Load test dataset
df = pd.read_csv(TEST_CSV)

# Protocol encoding map
proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
df["proto"] = df["proto"].map(lambda x: proto_map.get(str(x).lower(), 0))

# Encode categorical columns as in training
for col in ["service", "state"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))

feature_cols = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb",
    "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
]

# Drop rows missing any feature or label
df = df.dropna(subset=feature_cols + ["label"])

# Ensure label is integer
df["label"] = df["label"].astype(int)

X = df[feature_cols].values
y = df["label"].values

# Scale features once
X_scaled = scaler.transform(X)

# Create DQN agent
state_dim  = len(feature_cols)
action_dim = 2   # 0 = allow, 1 = block
agent = DQNAgent(state_dim, action_dim)

# Metrics
cumulative_reward = 0

def simulate_packet_stream():
    global cumulative_reward

    for idx, (state, true_label) in enumerate(zip(X_scaled, y)):
        # Agent selects action
        action = agent.select_action(state)

        # Binary model prediction
        binary_pred = binary_model.predict(state.reshape(1, -1))[0]
        
        # Attack category prediction (only if binary predicts attack)
        attack_category = "N/A"
        if binary_pred == 1:
            cat_pred = attack_cat_model.predict(state.reshape(1, -1))[0]
            attack_category = attack_cat_encoder.inverse_transform([cat_pred])[0]

        # Compute reward
        reward = 1 if (action == true_label) else -1
        cumulative_reward += reward

        # Next state: here we use the next row; if at end, reuse same
        next_state = X_scaled[idx + 1] if idx + 1 < len(X_scaled) else state

        # Done flag at end of dataset
        done = (idx == len(X_scaled) - 1)

        # Store experience and train
        agent.store(state, action, reward, next_state, done)
        agent.train_step()

        # Periodically update target network
        if idx % 100 == 0:
            agent.update_target()        # Yield a structured dictionary for streaming
        yield {
            "index": idx,
            "prediction": int(binary_pred),
            "attack_category": attack_category,
            "true_label": int(true_label),
            "action": action,
            "reward": reward,
            "cumulative_reward": cumulative_reward
        }

        # Simulate real-time delay
        time.sleep(0.1)
