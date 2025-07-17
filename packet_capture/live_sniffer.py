from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time

# List to hold packet data
packet_data = []

# Number of packets to capture before saving
PACKET_LIMIT = 500
OUTPUT_CSV = "../data/captured_packets.csv"

# Packet processing function
def extract_features(pkt):
    if IP in pkt:
        proto = pkt[IP].proto
        length = len(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        src_port = None
        dst_port = None

        if TCP in pkt or UDP in pkt:
            src_port = pkt.sport
            dst_port = pkt.dport

        features = {
            "srcip": src_ip,
            "dstip": dst_ip,
            "sport": src_port,
            "dsport": dst_port,
            "proto": proto,
            "pktsize": length,
        }

        packet_data.append(features)

        if len(packet_data) >= PACKET_LIMIT:
            save_packets()

# Save to CSV
def save_packets():
    df = pd.DataFrame(packet_data)
    df.fillna(0, inplace=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n✅ Saved {len(df)} packets to {OUTPUT_CSV}")
    packet_data.clear()

# Start sniffing
if __name__ == "__main__":
    print("📡 Starting packet capture...")
    try:
        sniff(prn=extract_features, store=False)
    except KeyboardInterrupt:
        print("\n⏹️ Stopping capture...")
        save_packets()
