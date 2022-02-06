import socket 
import traceback
from scapy.all import *

from tunnel_base import TunnelBase
from icmp_server import IcmpServer
from iptables import IPTableManager, IPTablesICMPRule
from consts import ICMP_BUFFER_SIZE, TCP_BUFFER_SIZE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST


class ProxyServer(TunnelBase):
    def __init__(self):
        self.proxy_icmp_socket = IcmpServer.create_icmp_socket()
        self.sockets = [self.proxy_icmp_socket]
        self.tcp_socket = None

    def _create_tcp_socket(self, remote_dst_host, remote_dst_port):
        print("[ProxyServer] Creating new TCP socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((remote_dst_host, remote_dst_port))

        return sock

    def _close_conenction(self):
        print(f"[ProxyServer] Disconnecting")
        self.sockets.remove(self.tcp_socket)
        self.tcp_socket.close()
        self.tcp_socket = None

    def icmp_data_handler(self, sock, ip_table_handler:IPTableManager):
        print("[ProxyServer] ICMP data handler")
        assert sock == self.proxy_icmp_socket, "WTF"

        try:
            packet = IcmpServer.parse_icmp_packet(self.proxy_icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])
            print(f"[ProxyServer] Parsed packet")

            self.proxy_client_host = packet.src_host
            self.remote_dst_host = packet.remote_dst_host
            self.remote_dst_port = packet.remote_dst_port
            if packet.icmp_type == ICMP_ECHO_REQUEST:
                if len(packet.data) == 0:
                    print("[ProxyServer] Disconnect request received from client")
                    self._close_conenction()
                else:
                    if not self.tcp_socket:
                        self.tcp_socket = self._create_tcp_socket(self.remote_dst_host, self.remote_dst_port)
                        #rule = IPTablesLoopbackRule(self.remote_dst_host, is_server=True)
                        #ip_table_handler.add_rule(rule)
                        self.sockets.append(self.tcp_socket)
                    print("[ProxyServer] Sending data from client over TCP socket")
                    self.tcp_socket.send(packet.data)
            else:
                print(f'Wrong ICMP type: {packet.icmp_type}')
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            pass

    def tcp_data_handler(self, sock):
        print("[ProxyServer] Received data on TCP socket")
        assert sock == self.tcp_socket, "WTF"

        try: 
            data = self.tcp_socket.recv(TCP_BUFFER_SIZE)
        except ConnectionResetError as e:
            print(f"[ProxyClientThread] {e}")
            data = b''

        print("[ProxyClientThread] Building ICMP packet")
        packet = IcmpServer.build_icmp_packet(icmp_type=ICMP_ECHO_REPLY, dst_host=self.proxy_client_host, data=data)

        print("[ProxyServer] Sending received data over ICMP connection")
        send(packet)

        if len(data) == 0:
            self._close_conenction()
