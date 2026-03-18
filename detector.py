from collections import defaultdict
from dashboard import alert

scan_tracker = defaultdict(set)
syn_counter = defaultdict(int)

PORT_SCAN_THRESHOLD = 20
SYN_THRESHOLD = 100

def detect_portscan(src, port):

    scan_tracker[src].add(port)

    if len(scan_tracker[src]) > PORT_SCAN_THRESHOLD:
        alert(f"Port scan detected from {src}")

def detect_syn_flood(src, flags):

    if flags == "S":
        syn_counter[src] += 1

        if syn_counter[src] > SYN_THRESHOLD:
            alert(f"SYN flood detected from {src}")
