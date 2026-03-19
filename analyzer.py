from collections import defaultdict
from scapy.layers.inet import IP, TCP

PORT_SCAN_THRESHOLD = 20
SYN_THRESHOLD = 100

def analyze_packets(packets):

    port_tracker = defaultdict(set)
    syn_counter = defaultdict(int)
    traffic_counter = defaultdict(int)

    results = []

    for packet in packets:

        if packet.haslayer(IP):

            src = packet[IP].src
            traffic_counter[src] += 1   # NEW: count packets per IP

            if packet.haslayer(TCP):

                port = packet[TCP].dport
                flags = packet[TCP].flags

                port_tracker[src].add(port)

                if flags & 0x02:  # SYN flag
                    syn_counter[src] += 1

    # Detect port scan
    for ip, ports in port_tracker.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            results.append(f"Port scan detected from {ip}")

    # Detect SYN flood
    for ip, syns in syn_counter.items():
        if syns > SYN_THRESHOLD:
            results.append(f"SYN flood detected from {ip}")

    return results, traffic_counter
