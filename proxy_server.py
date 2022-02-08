import socket 
import traceback
from scapy.all import *

from loopback_socket import LoopbackSocket
from tunnel_base import TunnelBase
from icmp_server import IcmpServer
from consts import ICMP_BUFFER_SIZE, TCP_BUFFER_SIZE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST


class ProxyServer(TunnelBase):
    def __init__(self):
        self.icmp_socket = IcmpServer.create_icmp_socket()
        self.tcp_socket = None

        self.sockets = [self.icmp_socket]

        TunnelBase.__init__(self)

    def _open_tcp_socket(self, remote_dst_port):
        print("[ProxyServer] Creating new TCP socket")
        self.tcp_socket = LoopbackSocket(remote_dst_port, is_server=True)

        self.sockets.append(self.tcp_socket.socket)

    def icmp_data_handler(self, sock):
        print("[ProxyServer] ICMP data handler")
        assert sock == self.icmp_socket, "Unexpected socket Got ICMP from different socket then the one we know"

        try:
            packet = IcmpServer.parse_icmp_packet(self.icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])
            print(f"[ProxyServer] Parsed packet")
            self.proxy_client_host = packet.src_host

            if packet.icmp_type == ICMP_ECHO_REQUEST:
                if not self.tcp_socket:
                    self._open_tcp_socket(packet.remote_dst_port)
                print("[ProxyServer] Sending data from client over TCP socket")
                self.tcp_socket.send(packet.data)
            else:
                print(f'Wrong ICMP type: {packet.icmp_type}')
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            pass

    def tcp_data_handler(self, sock):
        assert sock == self.tcp_socket.socket, "Unexpected socket Got TCP from different socket then the one we know"

        data = self.tcp_socket.recv()
        if data:
            print("[ProxyServer] Received data on TCP socket. Sending over ICMP connection")
            send(IcmpServer.build_icmp_packet(icmp_type=ICMP_ECHO_REPLY, dst_host=self.proxy_client_host, data=self.tcp_socket.recv()))