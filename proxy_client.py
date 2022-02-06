import socket 
from scapy.all import *

from tunnel_base import TunnelBase
from icmp_server import IcmpServer
from iptables import IPTableManager, IPTablesICMPRule
from consts import ICMP_BUFFER_SIZE, TCP_BUFFER_SIZE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST

class disconnectedException(Exception):
    pass

class ProxyClient(TunnelBase):
    def _create_tcp_listening_socket(self, listen_port):
        print(f"[ProxyClient] Creating TCP socket {'0.0.0.0', listen_port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', listen_port))

        return sock

    def __init__(self, proxy_server_host, listen_port, remote_server_host, remote_server_port):
        self.remote_server_host = remote_server_host
        self.remote_server_port = remote_server_port
        self.proxy_server_host = proxy_server_host

        self.tcp_socket = self._create_tcp_listening_socket(listen_port)
        self.icmp_socket = IcmpServer.create_icmp_socket()
        self.tcp_client_socket = None

        self.sockets = [self.icmp_socket]

        TunnelBase.__init__(self)

    def _close_tcp_client_socket(self):
        self.tcp_client_socket.close()
        self.sockets.remove(self.tcp_client_socket)
    
    def _open_tcp_client_socket(self, new_socket):
        self.tcp_client_socket = new_socket
        self.sockets.append(self.tcp_client_socket)

    def icmp_data_handler(self, sock, ip_table_handler:IPTableManager):
        print("[ProxyClientThread] icmp_data_handler")
        assert sock == self.icmp_socket, "Unexpected socket Got ICMP from different socket then the one we know"
        try:
            packet = IcmpServer.parse_icmp_packet(self.icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])

            if packet.icmp_type == ICMP_ECHO_REPLY:
                print("[ProxyClientThread] Parsed ICMP packet from proxy server")
                if len(packet.data) == 0:
                    print("[ProxyClientThread] Remote Host Disconnected")
                    raise disconnectedException()
                self.tcp_client_socket.send(packet.data)
        except ValueError:
            # Bad packet, malformated, not our, EOF etc..
            return

    def tcp_data_handler(self, sock):
        print("[ProxyClientThread] tcp_data_handler")
        assert sock == self.tcp_client_socket, "Unexpected socket Got TCP from different socket then the one we know"
        data = self.tcp_client_socket.recv(TCP_BUFFER_SIZE)

        print("[ProxyClientThread] Building ICMP packet")
        packet = IcmpServer.build_icmp_packet(icmp_type=ICMP_ECHO_REQUEST, dst_host=self.proxy_server_host, 
            remote_dst_host=self.remote_server_host, remote_dst_port=self.remote_server_port, data=data)

        print("[ProxyClientThread] sending ICMP packet to proxy server")
        send(packet)

        if len(data) == 0:
            print("[ProxyClientThread] Disconnected")
            raise disconnectedException()

    def run(self):
        # main loop
        print("[ProxyClient] Entering main loop")
        with IPTableManager() as ip_table:
            #rule = IPTablesLoopbackRule(port=self.tcp_socket.getsockname()[1], is_server=False)
            #ip_table.add_rule(rule)
            while True:
                self.tcp_socket.listen(1)
                sock, addr = self.tcp_socket.accept()
                print("[ProxyClient] New connection!")
                try:
                    self._open_tcp_client_socket(sock)
                    self.runTunnel()
                except disconnectedException:
                    self._close_tcp_client_socket()
