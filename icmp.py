import socket
import struct

ICMP_ECHO = 0
ICMP_ECHO_REQUEST = 8

IP_HEADER_FORMAT = "BBHHHBBH4s4s"
ICMP_HEADER_FORMAT = "!BBHHH4sH"

class ICMPPacket(object):
    def __init__(self, icmp_type, code, checksum, packet_id,
                 sequence, data, src_ip, dst=(None, None)):
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.packet_id = packet_id
        self.sequence = sequence
        self.data = data
        self.dst_ip, self.dst_port = dst
        self.src_ip = src_ip
        self.length = len(self.data)

    def create(self):
        pack_str = "!BBHHH4sH"
        pack_args = [self.icmp_type, self.code, 0, self.packet_id, self.sequence,
                     socket.inet_aton(socket.gethostbyname(self.dst_ip)), self.dst_port]

        if self.length:
            pack_str += "{}s".format(self.length)
            pack_args.append(self.data)

        self.checksum = self._checksum(struct.pack(pack_str, *pack_args)) 
        pack_args[2] = self.checksum
        return struct.pack(pack_str, *pack_args)

    @classmethod
    def parse(cls, packet):
        data = b""

        ip_header, icmp_header = packet[:20], packet[20:] # split ip header

        ip_header = struct.unpack(IP_HEADER_FORMAT, ip_header)

        src_ip = ip_header[8]
        icmp_header_len = struct.calcsize(ICMP_HEADER_FORMAT)
        data_len = len(icmp_header) - icmp_header_len

        if data_len > 0:
            data = "{}s".format(data_len)
            data = struct.unpack(data, icmp_header[icmp_header_len:])[0]

        icmp_type, code, checksum, packet_id, sequence, dst_ip, dst_port = \
            struct.unpack(ICMP_HEADER_FORMAT, icmp_header[:icmp_header_len])

        return cls(icmp_type, code, checksum, packet_id, sequence, data,
                   socket.inet_ntoa(src_ip),
                   (socket.inet_ntoa(dst_ip), dst_port))


    @staticmethod
    def _checksum(packet):
        csum = 0
        countTo = (len(packet) / 2) * 2
        count = 0

        while count < countTo:
            thisVal = packet[count+1] * 256 + packet[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(packet):
            csum = csum + ord(packet[len(packet) - 1])
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        checksum = ~csum
        checksum = checksum & 0xffff
        checksum = checksum >> 8 | (checksum << 8 & 0xff00)
        return checksum