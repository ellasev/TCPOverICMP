import socket
import select
from iptables import IPTablesLoopbackRule

from iptables import IPTableManager, IPTablesICMPRule

class TunnelBase():
    def icmp_data_handler(self, sock):
        print(f"[Tunnel] icmp_data_handler: {sock.recv()}")

    def tcp_data_handler(self, sock):
        print(f"[Tunnel] tcp_data_handler: {sock.recv()}")

    def run(self, is_server:bool):
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
