import numpy as np
import pandas as pd
from rl_agent.environment import CyberSecurityEnv
from rl_agent.dqn_model import DQNAgent

EPISODES = 20
BATCH_SIZE = 32
MODEL_PATH = "../model/dqn_agent.h5"

# Step 1: Load preprocessed data (same format as XGBoost input)
def load_data():
    df = pd.read_csv("../data/UNSW_NB15_training-set.csv")
    features = df[['sport', 'dsport', 'proto', 'pktsize']].copy()
    features.fillna(0, inplace=True)

    # Encode protocol if needed
    from sklearn.preprocessing import LabelEncoder
    if features['proto'].dtype == 'object':
        features['proto'] = LabelEncoder().fit_transform(features['proto'])

    X = features.to_numpy()
    y = df['label'].values
    return X, y

# Step 2: Initialize
X, y = load_data()
env = CyberSecurityEnv(X, y)
agent = DQNAgent(state_size=env.state_size, action_size=len(env.action_space))

# Step 3: Training Loop
for e in range(EPISODES):
    state = env.reset()
    total_reward = 0

    while True:
        action = agent.act(state)
        next_state, reward, done = env.step(action)

        agent.remember(state, action, reward, next_state, done)
        agent.replay(BATCH_SIZE)

        state = next_state
        total_reward += reward

        if done:
            print(f"Episode {e+1}/{EPISODES} - Total Reward: {total_reward}, Epsilon: {agent.epsilon:.2f}")
            break

# Step 4: Save the trained model
agent.save(MODEL_PATH)
print(f"✅ DQN model saved to {MODEL_PATH}")
