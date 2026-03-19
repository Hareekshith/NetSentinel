from sniffer import start_sniffing
from analyzer import analyze_packets
from dashboard import banner, show_results, show_traffic_summary

def main():

    banner()

    packets = start_sniffing()

    print("\nAnalyzing packets...\n")

    results, traffic_counter = analyze_packets(packets)

    show_traffic_summary(traffic_counter)

    show_results(results)

if __name__ == "__main__":
    main()
