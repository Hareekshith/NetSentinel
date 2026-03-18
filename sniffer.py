from scapy.all import sniff
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

    sniff(prn=process_packet, store=False)
