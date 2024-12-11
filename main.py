from scapy.all import sniff, IP, TCP

# Function to process packets
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            print(f"[TCP] {ip_src}:{tcp_src_port} -> {ip_dst}:{tcp_dst_port}")
        else:
            print(f"[IP] {ip_src} -> {ip_dst}")

# Sniff packets
print("Starting packet sniffer...")
sniff(filter="ip", prn=packet_callback, store=0)
