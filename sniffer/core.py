import logging
from scapy.all import sniff, wrpcap
from scapy.layers.http import HTTPRequest
from colorama import Fore, Style
from sniffer.analyzer import PacketAnalyzer
from sniffer.exceptions import SnifferError
from outputs.pcap_handler import PCAPHandler
from config.constants import PROTOCOL_COLORS

class PacketSniffer:
    def __init__(self, interface, filter_exp="", output_file="", packet_limit=0, logger=None):
        self.interface = interface
        self.filter_exp = filter_exp
        self.output_file = output_file
        self.packet_limit = packet_limit
        self.logger = logger or logging.getLogger(__name__)
        self.packets = []
        self.running = False

    def _packet_handler(self, packet):
        if self.packet_limit > 0 and len(self.packets) >= self.packet_limit:
            self.running = False
            return
        
        self.packets.append(packet)
        analysis = PacketAnalyzer.analyze(packet)
        self._log_packet(analysis)

    def _log_packet(self, analysis):
        color = PROTOCOL_COLORS.get(analysis['protocol'], Fore.WHITE)
        log_msg = (
            f"{color}[PACKET #{len(self.packets)}] "
            f"{analysis['src_ip']}:{analysis['src_port']} → "
            f"{analysis['dst_ip']}:{analysis['dst_port']} | "
            f"{analysis['protocol']}{Style.RESET_ALL}"
        )
        
        if analysis['http_info']:
            log_msg += f" | {Fore.CYAN}{analysis['http_info']}{Style.RESET_ALL}"
        
        self.logger.info(log_msg)

    def start(self):
        if not self.interface:
            raise SnifferError("Network interface not specified")
        
        self.logger.info(f"Starting PySniffer-X on {self.interface}...")
        self.logger.info(f"Filter: {self.filter_exp or 'None'}")
        self.logger.info("Press Ctrl+C to stop...")
        
        self.running = True
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_exp,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            raise SnifferError(f"Sniffing failed: {str(e)}")
        finally:
            if self.output_file and self.packets:
                PCAPHandler.save(self.packets, self.output_file)
                self.logger.info(f"Saved {len(self.packets)} packets to {self.output_file}.pcap")
            
            self.logger.info(f"Capture complete. Total packets: {len(self.packets)}")