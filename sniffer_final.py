from scapy.all import sniff, IP, TCP, UDP

log_file = open("traffic_log.txt", "a")

def packet_callback(packet):

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):

            port = packet[TCP].dport
            protocol = "TCP"

        elif packet.haslayer(UDP):

            port = packet[UDP].dport
            protocol = "UDP"

        else:
            return

        log = f"{src} -> {dst} | {protocol} | Port {port}"

        print(log)

        log_file.write(log + "\n")

print("Packet sniffer running...")
sniff(prn=packet_callback,count=500)