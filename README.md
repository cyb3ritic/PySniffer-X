# PySniffer-X 🕵️‍♂️

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)


**Professional-grade packet sniffer** with deep inspection, real-time analysis, and Wireshark integration. Designed for network analysis, cybersecurity education, and ethical hacking.


## Features ✨

- 🕵️‍♂️ **Live packet capture** (TCP, UDP, ICMP, HTTP, DNS)
- 🔍 **Deep Packet Inspection (DPI)** with protocol analysis
- 📊 **Real-time traffic dashboard** with colored output
- 🎚️ **Custom BPF filters** (IP, port, protocol)
- 💾 **PCAP export** for Wireshark analysis
- ⚡ **Performance optimized** with Scapy
- 📝 **Detailed logging** with verbosity control

## Installation 🛠️

### Prerequisites
- Python 3.8+
- Linux/macOS (Windows requires WinPcap/Npcap)
- Root/sudo privileges (for raw socket access)

### Quick Start
```bash
# Clone repository
git clone https://github.com/yourusername/PySniffer-X.git
cd PySniffer-X

# Install dependencies
pip install -r requirements.txt

# Run with default interface
sudo python3 main.py -i eth0