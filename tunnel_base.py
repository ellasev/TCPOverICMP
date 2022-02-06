import socket
import threading

from iptables import IPTableManager, IPTablesICMPRule

class TunnelBase(threading.Thread):
    def icmp_data_handler(self, sock):
        print(f"[Tunnel] icmp_data_handler: {sock.recv()}")

    def tcp_data_handler(self, sock):
        print(f"[Tunnel] tcp_data_handler: {sock.recv()}")

    def run(self):
        print("[Tunnel] main loop")
        with IPTableManager() as ip_table_manager:
            print(self.proxy_icmp_socket.getsockname())
            icmp_rule = IPTablesICMPRule(ip=self.proxy_icmp_socket.getsockname()[0])
            ip_table_manager.add_rule(icmp_rule)

            while True:
                read, _, _ = select.select(self.sockets, [], [])
                for sock in read:
                    if sock.proto == socket.IPPROTO_ICMP:
                        self.icmp_data_handler(sock, ip_table_manager)
                    else:
                        self.tcp_data_handler(sock)
