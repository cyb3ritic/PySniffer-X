#!/usr/bin/env python3
import argparse
from sniffer.core import PacketSniffer
from outputs.logger import setup_logger
from config.settings import Settings

def parse_args():
    parser = argparse.ArgumentParser(
        description="PySniffer-X: Advanced Network Packet Sniffer",
        epilog="Example: sudo python3 main.py -i eth0 -f 'tcp port 80' -o capture"
    )
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g., eth0)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("-o", "--output", default="", help="Save to PCAP file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packet count limit (0=unlimited)")
    return parser.parse_args()

def main():
    args = parse_args()
    Settings.LOG_LEVEL = "DEBUG" if args.verbose else "INFO"
    
    logger = setup_logger()
    sniffer = PacketSniffer(
        interface=args.interface,
        filter_exp=args.filter,
        output_file=args.output,
        packet_limit=args.count,
        logger=logger
    )
    
    try:
        sniffer.start()
    except KeyboardInterrupt:
        logger.info("Sniffer stopped by user")
    except Exception as e:
        logger.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()