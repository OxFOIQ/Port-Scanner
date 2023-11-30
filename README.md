# Port-Scanner
EPISCAN is a versatile port scanner written in Python, offering a range of features to identify open ports, detect operating systems, and determine service versions on target IP addresses.

Features

Efficient multithreaded scanning using concurrent.futures

*Scans all ports (1 to 65535) or specific ports

*Identifies open ports using sockets

*Detects operating systems using nmap

*Determines service versions using nmap

*Eye-catching banner using pyfiglet

*User-friendly interface and clear output


Installation

1/Install Python 3.x (https://www.python.org/downloads/)

2/Install the required libraries using pip:

pip install pyfiglet socket concurrent.futures nmap


Usage

Run the EpiScan.py script from the project directory.

Enter the target IP address when prompted.

Choose between full scan (all ports) or specific port scan.

For specific port scan, enter the desired ports .

The scanning results and timestamps will be displayed.


Contributing

Contributions are welcome! Please follow the project's coding style guidelines and submit pull requests via GitHub.
