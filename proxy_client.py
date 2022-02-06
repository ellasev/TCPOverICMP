import socket 
from scapy.all import *

from tunnel_base import TunnelBase
from icmp_server import IcmpServer
from iptables import IPTableManager, IPTablesICMPRule
from consts import ICMP_BUFFER_SIZE, TCP_BUFFER_SIZE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST

class ProxyClientThread(TunnelBase):
    def __init__(self, proxy_server_host, tcp_socket, proxy_icmp_socket, remote_server_host, remote_server_port):
        self.proxy_server_host = proxy_server_host
        self.tcp_socket = tcp_socket
        self.proxy_icmp_socket = proxy_icmp_socket
        self.remote_server_host = remote_server_host
        self.remote_server_port = remote_server_port
        self.sockets = [tcp_socket, proxy_icmp_socket]

        Tunnel.__init__(self)

    def close(self):
        self.tcp_socket.close()
        exit()

    def icmp_data_handler(self, sock, ip_table_handler:IPTableManager):
        print("[ProxyClientThread] icmp_data_handler")
        assert sock == self.proxy_icmp_socket, "WTF"
        try:
            packet = IcmpServer.parse_icmp_packet(self.proxy_icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])

            if packet.icmp_type == ICMP_ECHO_REPLY:
                print("[ProxyClientThread] Parsed ICMP packet from proxy server")
                if len(packet.data) == 0:
                    print("[ProxyClientThread] Remote Host Disconnected")
                    self.close()
                self.tcp_socket.send(packet.data)
        except ValueError:
            # Bad packet, malformated, not our, EOF etc..
            return

    def tcp_data_handler(self, sock):
        print("[ProxyClientThread] tcp_data_handler")
        assert sock == self.tcp_socket, "WTF"
        data = self.tcp_socket.recv(TCP_BUFFER_SIZE)

        print("[ProxyClientThread] Building ICMP packet")
        packet = IcmpServer.build_icmp_packet(icmp_type=ICMP_ECHO_REQUEST, dst_host=self.proxy_server_host, 
            remote_dst_host=self.remote_server_host, remote_dst_port=self.remote_server_port, data=data)

        print("[ProxyClientThread] sending ICMP packet to proxy server")
        send(packet)

        if len(data) == 0:
            print("[ProxyClientThread] Disconnected")
            self.close()
        

class ProxyClient():
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

        self.proxy_tcp_socket = self._create_tcp_listening_socket(listen_port)
        self.proxy_icmp_socket = IcmpServer.create_icmp_socket()

    def run(self):
        # main loop
        print("[ProxyClient] Entering main loop")
        with IPTableManager() as ip_table:
            #rule = IPTablesLoopbackRule(port=self.proxy_tcp_socket.getsockname()[1], is_server=False)
            #ip_table.add_rule(rule)
            while True:
                self.proxy_tcp_socket.listen(5)
                sock, addr = self.proxy_tcp_socket.accept()
                print("[ProxyClient] New connection!")
                new_thread = ProxyClientThread(self.proxy_server_host, sock, self.proxy_icmp_socket, self.remote_server_host, self.remote_server_port)
                new_thread.start()
