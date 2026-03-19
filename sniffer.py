from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP

from detector import detect_portscan, detect_syn_flood
from dashboard import show_packet

def process_packet(packet):

    if packet.haslayer(IP):

        src = packet[IP].src

        if packet.haslayer(TCP):

            port = packet[TCP].dport
            flags = packet[TCP].flags

            show_packet(src, port)

            detect_portscan(src, port)
            detect_syn_flood(src, flags)

def start_sniffing():

    interfaces = get_if_list()

    print(f"Sniffing on interfaces: {interfaces}\n")

    packets = sniff(
        iface=interfaces,
        filter="tcp",
        timeout=60
    )

    print(f"Captured {len(packets)} packets")

    return packets
