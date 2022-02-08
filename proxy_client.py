from iptables import IPTableManager
from scapy.all import *

from loopback_socket import LoopbackSocket
from tunnel_base import TunnelBase
from icmp_server import IcmpServer
from consts import ICMP_BUFFER_SIZE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST


class ProxyClient(TunnelBase):
    """
    Implements the Client side of the ICMP TCP proxy
    """
    def __init__(self, proxy_server_host, listen_port, remote_server_port):
        """
        Initiates the different paramters in the proxy client.
        Opens the ICMP and TCP sockets.

        :param proxy_server_host - host to create the tunnel with
        :param listen_port - port to listen to for TCP connections
        """
        self.remote_server_port = remote_server_port
        self.proxy_server_host = proxy_server_host

        self.tcp_socket = LoopbackSocket(listen_port, is_server=False)
        self.icmp_socket = IcmpServer.create_icmp_socket()

        self.sockets = [self.icmp_socket, self.tcp_socket.socket]

        TunnelBase.__init__(self)

    def icmp_data_handler(self, sock, iptable_manager:IPTableManager):
        """
        Receives from ICMP socket and writes to TCP socket

        :param sock - socket to receive from
        :param iptable_manager - manages IPTables rules. more under iptables.py
        """
        assert sock == self.icmp_socket, "Unexpected socket Got ICMP from different socket then the one we know"
        try:
            packet = IcmpServer.parse_icmp_packet(self.icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])

            if packet.icmp_type == ICMP_ECHO_REPLY:
               # print("[ProxyClient] Parsed ICMP packet from proxy server")
                self.tcp_socket.send(packet.data)
        except ValueError:
            # Bad packet, malformated, not our, EOF etc..
            return

    def tcp_data_handler(self, sock):
        """
        Receives from TCP socket and writes to ICMP socket

        :param sock - socket to receive from
        """
        assert sock == self.tcp_socket.socket, "Unexpected socket Got TCP from different socket then the one we know"

        data = self.tcp_socket.recv()
        if data:
            #print("[ProxyClient] Received data on TCP socket. Sending over ICMP connection")
            send(IcmpServer.build_icmp_packet(icmp_type=ICMP_ECHO_REQUEST, dst_host=self.proxy_server_host, 
                remote_dst_port=self.listen_port, data=data))
