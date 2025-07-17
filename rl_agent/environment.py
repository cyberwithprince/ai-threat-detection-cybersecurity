import numpy as np
from collections import deque
import random

class CyberSecurityEnv:
    def __init__(self, packets, labels):
        self.packets = packets                # list of feature vectors (numpy)
        self.labels = labels                  # list of ground-truth attack labels
        self.current_index = 0
        self.action_space = [0, 1]            # 0 = Allow, 1 = Block
        self.state_size = packets.shape[1]    # e.g., 5 features
        self.reset()

    def reset(self):
        self.current_index = 0
        return self.packets[self.current_index]

    def step(self, action):
        done = False
        state = self.packets[self.current_index]
        label = self.labels[self.current_index]

        # Define reward logic
        if action == 1 and label == 1:
            reward = 1   # correctly blocked attack
        elif action == 0 and label == 0:
            reward = 1   # correctly allowed benign
        else:
            reward = -1  # incorrect decision

        self.current_index += 1

        if self.current_index >= len(self.packets):
            done = True
            next_state = np.zeros(self.state_size)
        else:
            next_state = self.packets[self.current_index]

        return next_state, reward, done
