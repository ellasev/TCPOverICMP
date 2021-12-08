import socket
import struct
from scapy.all import IP, ICMP

ICMP_ECHO = 0
ICMP_ECHO_REQUEST = 8

IP_HEADER_FORMAT = "BBHHHBBH4s4s"
ICMP_HEADER_FORMAT = "!BBHHH4sH"

class ICMPPacket(object):
    def __init__(self, icmp_type, code, src_ip, dst_host=None, dst_port=None, data=None):
        self.icmp_type = icmp_type
        self.code = code
        self.src_ip = src_ip
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.data = data

    def create(self):
        pack_str = "!BBHHH4sH"
        pack_args = [self.icmp_type, self.code, 0, 0, 0,
                     socket.inet_aton(socket.gethostbyname(self.dst_host)), self.dst_port]

        if len(self.data):
            pack_str += "{}s".format(len(self.data))
            pack_args.append(self.data)

        checksum = self._checksum(struct.pack(pack_str, *pack_args))
        pack_args[2] = checksum
        return struct.pack(pack_str, *pack_args)

    @classmethod
    def parse(cls, packet):
        data = b""

        ip_header, icmp_header = packet[:20], packet[20:]
        ip_header = struct.unpack(IP_HEADER_FORMAT, ip_header)
        src_ip = ip_header[8]

        icmp_header_len = struct.calcsize(ICMP_HEADER_FORMAT)
        data_len = len(icmp_header) - icmp_header_len

        if data_len > 0:
            data = "{}s".format(data_len)
            data = struct.unpack(data, icmp_header[icmp_header_len:])[0]

        icmp_type, code, checksum, packet_id, sequence, dst_host, dst_port = \
            struct.unpack(ICMP_HEADER_FORMAT, icmp_header[:icmp_header_len])

        return cls(icmp_type, code, socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_host), dst_port, data)

    @staticmethod
    def _checksum(data):
        checksum = 0
        data += b'\x00'

        for i in range(0, len(data) - 1, 2):
            checksum += (data[i] << 8) + data[i + 1]
            checksum = (checksum & 0xffff) + (checksum >> 16)

        checksum = ~checksum & 0xffff

        return checksum
