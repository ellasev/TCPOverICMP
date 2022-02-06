import struct 
import socket 
from scapy.all import *

class ParsedIcmpPacket():
    def __init__(self, icmp_type, src_host):
        self.icmp_type = icmp_type
        self.src_host = src_host
        self.remote_dst_host = None
        self.remote_dst_port = None
        self.data = None

class IcmpServer():
    @staticmethod
    def create_icmp_socket():
        print("[IcmpServer] Creating ICMP socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        return sock

    @staticmethod
    def parse_icmp_packet(data):
        packet = IP(data)
        assert packet[ICMP].id == ICMP_ID, "Wrong ICMP ID"

        parsed_packet = ParsedIcmpPacket(icmp_type = packet[ICMP].type, src_host = packet[IP].src)
        struct_size = struct.calcsize("4sH")
        payload = bytes(packet[ICMP].payload)

        parsed_packet.remote_dst_host, parsed_packet.remote_dst_port = struct.unpack("4sH", payload[:struct_size])
        parsed_packet.data = payload[struct_size:]
        parsed_packet.remote_dst_host = socket.inet_ntoa(parsed_packet.remote_dst_host)

        return parsed_packet

    @staticmethod
    def build_icmp_packet(icmp_type, dst_host, remote_dst_host='0.0.0.0', remote_dst_port=0, data=''):
        payload = struct.pack("4sH", socket.inet_aton(remote_dst_host), remote_dst_port) + data
        return IP(dst = dst_host) / ICMP(id=ICMP_ID, type=icmp_type, seq=1) / payload
        
