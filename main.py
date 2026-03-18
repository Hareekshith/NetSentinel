from dashboard import show_banner
from sniffer import start_sniffing

def main():

    show_banner()

    print("Monitoring network traffic...\n")

    start_sniffing()

if __name__ == "__main__":
    main()
