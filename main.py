from sniffer import start_sniffing
from analyzer import analyze_packets
from dashboard import banner, show_results

def main():

    banner()

    packets = start_sniffing()

    print("Analyzing packets...\n")

    results = analyze_packets(packets)

    show_results(results)

if __name__ == "__main__":
    main()
