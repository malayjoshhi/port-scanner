🛡️ Multi-Threaded TCP Port Scanner
A fast, lightweight, multi-threaded TCP Port Scanner written in Python. Designed for security auditing, network discovery, and reconnaissance.

Key Features:
Concurrent port scanning using Python ThreadPoolExecutor.
Banner grabbing to discover host software versions.
Customizable connection timeouts and JSON reports.

## 🚀 Quick Start

### 1. Clone the repository

### 2. Run the scanner
No external dependencies are required! Uses Python standard libraries.

# Scan default top ports (1-1024) on localhost
python main.py localhost

# Scan specific port range with high threads
python main.py scanme.nmap.org -sp 1 -ep 500 -t 200

# Save results to JSON
python main.py 192.168.1.1 -sp 20 -ep 100 -o scan_results.json

## 🔒 Disclaimer
This tool is created for educational and authorized testing purposes only. Scanning targets without prior mutual consent is illegal.

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
