# NetSentinel (A lightweight IDS)
This project has been designed to detect whether there is any reconnnaisance attacks performed by any IP's. 

## Components
- Python3
- Scapy

## Concept
- The Sniffer, scans the device for 60 seconds once started from main and stores it. 
- The detector, has two functions to check whether the anomaly is either a `SYN_flood` or a `Port_Scan`
- The Analyzer, uses the functions in the detector and the stored to packets to detect any anomalies
- The Dashboard, has a Terminal UI interface and uses the packets, summarises it and displays it in a nice table. 
- The MAIN, combines all the modules, the project should be run from main.

## Command
- Create a python virtual machine <br>
`python3 -m venv .venv`
- Install the pip modules <br>
`pip install -r requirements.txt`
- Run the program using sudo <br>
`sudo .venv/bin/python main.py`

## License
GNU Public License
