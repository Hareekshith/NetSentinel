from collections import defaultdict
import time
from dashboard import alert

PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 5
SYN_THRESHOLD = 100

scan_tracker = defaultdict(list)
syn_counter = defaultdict(int)

def detect_portscan(src, port):

    current_time = time.time()

    # store port + timestamp
    scan_tracker[src].append((port, current_time))

    # keep only recent entries
    scan_tracker[src] = [
        (p, t) for p, t in scan_tracker[src]
        if current_time - t < TIME_WINDOW
    ]

    unique_ports = {p for p, _ in scan_tracker[src]}

    if len(unique_ports) > PORT_SCAN_THRESHOLD:
        alert(f"Port scan detected from {src}")


def detect_syn_flood(src, flags):

    if flags & 0x02:  # SYN flag
        syn_counter[src] += 1

        if syn_counter[src] > SYN_THRESHOLD:
            alert(f"SYN flood detected from {src}")
