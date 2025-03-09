from scapy.all import IP, TCP, UDP, HTTP, ICMP,  HTTPRequest, HTTPResponse

class PacketAnalyzer:
    @staticmethod
    def analyze(packet):
        result = {
            'src_ip': '',
            'dst_ip': '',
            'src_port': '',
            'dst_port': '',
            'protocol': 'UNKNOWN',
            'http_info': ''
        }

        if IP in packet:
            result['src_ip'] = packet[IP].src
            result['dst_ip'] = packet[IP].dst

            if TCP in packet:
                result.update(PacketAnalyzer._analyze_tcp(packet))
            elif UDP in packet:
                result.update(PacketAnalyzer._analyze_udp(packet))
            elif ICMP in packet:
                result['protocol'] = 'ICMP'

            result['http_info'] = PacketAnalyzer._analyze_http(packet)

        return result

    @staticmethod
    def _analyze_tcp(packet):
        return {
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'protocol': 'TCP'
        }

    @staticmethod
    def _analyze_udp(packet):
        return {
            'src_port': packet[UDP].sport,
            'dst_port': packet[UDP].dport,
            'protocol': 'UDP'
        }

    @staticmethod
    def _analyze_http(packet):
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            return f"HTTP Request: {req.Host.decode()}{req.Path.decode()}"
        elif packet.haslayer(HTTPResponse):
            return "HTTP Response"
        return ""