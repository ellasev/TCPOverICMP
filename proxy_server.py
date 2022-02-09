import traceback
from iptables import IPTableManager, IPTablesLoopbackRule
from scapy.all import *

from loopback_socket import LoopbackSocket
from tunnel_base import TunnelBase
from icmp_server import IcmpServer
from consts import ICMP_BUFFER_SIZE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST


class ProxyServer(TunnelBase):
    """
    Implements the Server side of the ICMP TCP proxy
    """
    def __init__(self):
        """
        Initiates the different paramters in the proxy client.
        Opens the ICMP socket.
        """
        self.icmp_socket = IcmpServer.create_icmp_socket()
        self.tcp_socket = None

        self.sockets = [self.icmp_socket]

        TunnelBase.__init__(self)

    def _open_tcp_socket(self, remote_dst_port):
        """
        Open a tcp socket and appends it to listened sockets

        :param remote_dst_port: port to accept and write connection to. 
        """
        print("[ProxyServer] Creating new TCP socket")
        self.tcp_socket = LoopbackSocket(remote_dst_port, is_server=True)

        self.sockets.append(self.tcp_socket.socket)

    def icmp_data_handler(self, sock, iptable_manager:IPTableManager):
        """
        Receives from ICMP socket and writes to TCP socket.
        If needed, opens the TCP socket according to the parameters in the ICMP packet.

        :param sock - socket to receive from
        :param iptable_manager - manages IPTables rules. more under iptables.py
        """
        try:
            assert sock == self.icmp_socket, "Unexpected socket Got ICMP from different socket then the one we know"
            packet = IcmpServer.parse_icmp_packet(self.icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])
            self.proxy_client_host = packet.src_host

            if packet.icmp_type == ICMP_ECHO_REQUEST:
                if not self.tcp_socket:
                    self._open_tcp_socket(packet.remote_dst_port)
                    tcp_rule = IPTablesLoopbackRule(port=self.tcp_socket.listen_port, is_server=True)
                    iptable_manager.add_rule(tcp_rule)
                self.tcp_socket.send(packet.data)
            else:
                print(f'Wrong ICMP type: {packet.icmp_type}')
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            pass

    def tcp_data_handler(self, sock):
        """
        Receives from TCP socket and writes to ICMP socket

        :param sock - socket to receive from
        """
        assert sock == self.tcp_socket.socket, "Unexpected socket Got TCP from different socket then the one we know"

        data = self.tcp_socket.recv()
        if data:
            send(IcmpServer.build_icmp_packet(icmp_type=ICMP_ECHO_REPLY, dst_host=self.proxy_client_host, data=data))