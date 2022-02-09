import struct 
import socket 
from scapy.all import *

from consts import ICMP_ID

class ParsedIcmpPacket():
    """
    Packet info struct 
    """
    def __init__(self, icmp_type, src_host):
        self.icmp_type = icmp_type
        self.src_host = src_host
        self.remote_dst_port = None
        self.data = None

class IcmpServer():
    @staticmethod
    def create_icmp_socket():
        """
        Create the raw ICMP socket with the socket 
        """
        print("[IcmpServer] Creating ICMP socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        return sock

    @staticmethod
    def parse_icmp_packet(data):
        """
        Parse ICMP packet from data. 

        :param data - the whole packet.

        @return the parsed packet, a ParsedIcmpPacket object.
        """
        packet = IP(data)
        if packet[ICMP].id != ICMP_ID:
            print("Wrong ICMP ID")
            return

        parsed_packet = ParsedIcmpPacket(icmp_type = packet[ICMP].type, src_host = packet[IP].src)

        struct_size = struct.calcsize("H")
        payload = bytes(packet[ICMP].payload)
        parsed_packet.remote_dst_port = struct.unpack("H", payload[:struct_size])[0]
        parsed_packet.data = payload[struct_size:]

        return parsed_packet

    @staticmethod
    def build_icmp_packet(icmp_type, dst_host, remote_dst_port=0, data=''):
        """
        Build ICMP packet with scapy using the given parameters.

        :params icmp_type - the type of the ICMP packet we want to create
        :params dst_host - the dst host of the packet
        :params remote_dst_port - the dst port of the packet 
        :params data - data to put as the ICMP payload of the packet. This is the TCP packet. 

        @return built scapy packet 
        """
        payload = struct.pack("H", remote_dst_port) + data
        return IP(dst = dst_host) / ICMP(id=ICMP_ID, type=icmp_type, seq=1) / payload
        
