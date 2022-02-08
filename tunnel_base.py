import socket
import select
from iptables import IPTablesLoopbackRule

from iptables import IPTableManager, IPTablesICMPRule

class TunnelBase():
    """
    Base class of the tunnel object.
    Abstract class, Must be inherited. 
    """
    def icmp_data_handler(self, sock):
        """
        Function that is called from run and must be implemented by inherting classes. 
        Handles the recv in ICMP sockets

        :param sock - socket to receive from
        """
        raise NotImplementedError

    def tcp_data_handler(self, sock):
        """
        Function that is called from run and must be implemented by inherting classes. 
        Handles the recv in TCP sockets

        :param sock - socket to receive from
        """
        raise NotImplementedError

    def run(self, is_server:bool):
        """
        The tunnel loop, listens on the sockets specifies in self.sockets.
        Calls the icmp_data_handler and tcp_data_handler when one of the sockets is readable.

        :param is_server: Whether we are running as the proxy server or proxy client. 
        """
        print("[Tunnel] main loop")
        with IPTableManager() as ip_table_manager:
            icmp_rule = IPTablesICMPRule(ip=self.icmp_socket.getsockname()[0])
            ip_table_manager.add_rule(icmp_rule)
            if not is_server:
                tcp_rule = IPTablesLoopbackRule(port=self.tcp_socket.listen_port, is_server=False)
                ip_table_manager.add_rule(tcp_rule)
            while True:
                read, _, _ = select.select(self.sockets, [], [])
                for sock in read:
                    if type(sock) == socket.socket:
                        self.icmp_data_handler(sock, ip_table_manager)
                    else:
                        self.tcp_data_handler(sock)
