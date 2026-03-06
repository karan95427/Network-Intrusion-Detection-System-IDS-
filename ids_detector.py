import joblib
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime

# Load ML model (not used directly but part of project)
model = joblib.load("model.pkl")

print("Model loaded successfully")

# Track ports scanned by each IP
port_scan_tracker = defaultdict(set)

# Track already alerted attackers
alerted_ips = set()

# Packet counters
packet_count = defaultdict(int)
total_packets = 0

# Attack counter
attack_count = 0

# Alert log file
alert_file = open("alerts.txt", "a")


def show_top_talkers():
    print("\n------ Top Talkers ------")

    sorted_ips = sorted(packet_count.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:5]:
        print(f"{ip} : {count} packets")

    print("-------------------------\n")


def process_packet(packet):

    global attack_count
    global total_packets

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        # Ignore localhost traffic
        if src == "127.0.0.1" or dst == "127.0.0.1":
            return

        protocol = ""
        port = 0

        if packet.haslayer(TCP):
            protocol = "TCP"
            port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport

        print(f"{src} -> {dst} | {protocol} | Port {port}")

        # Count packets per IP
        packet_count[src] += 1
        total_packets += 1

        # Show top talkers every 20 packets
        if total_packets % 20 == 0:
            show_top_talkers()

        # Track ports accessed
        port_scan_tracker[src].add(port)

        # Detect port scan
        if len(port_scan_tracker[src]) > 20 and src not in alerted_ips:

            alerted_ips.add(src)
            attack_count += 1

            alert_message = f"""
ALERT: Possible Port Scan
Source IP: {src}
Ports scanned: {len(port_scan_tracker[src])}
Time: {datetime.now()}
Total attacks detected: {attack_count}
"""

            print(alert_message)

            alert_file.write(alert_message + "\n")
            alert_file.flush()


print("IDS Running...\n")

sniff(filter="ip and not host 127.0.0.1", prn=process_packet, store=False)