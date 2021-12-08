import argparse
import icmp
import select
import socket
import threading

PROXY_CLIENT_LISTENING_HOST = '127.0.0.1'

TCP_BUFFER_SIZE = 2 ** 10
ICMP_BUFFER_SIZE = 65565

class Tunnel(object):
    @staticmethod
    def create_icmp_socket():
        print("[Tunnel] Creating ICMP socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        return sock

    @staticmethod
    def create_tcp_socket(dst_host, dst_port, server=False):
        print("[Tunnel] Creating TCP socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((dst_host, dst_port)) if server else sock.connect((dst_host, dst_port))
        return sock

    def icmp_data_handler(self, sock):
        print(f"[Tunnel] icmp_data_handler: {sock.recv()}")

    def tcp_data_handler(self, sock):
        print(f"[Tunnel] tcp_data_handler: {sock.recv()}")

    def run(self):
        print("[Tunnel] main loop")
        while True:
            sread, _, _ = select.select(self.sockets, [], [])
            for sock in sread:
                if sock.proto == socket.IPPROTO_ICMP:
                    self.icmp_data_handler(sock)
                else:
                    self.tcp_data_handler(sock)

class Server(Tunnel):
    def __init__(self):
        self.tcp_socket = None
        self.src = None
        self.dst_host = None
        self.dst_port = None
        self.icmp_socket = self.create_icmp_socket()
        self.sockets = [self.icmp_socket]

    def icmp_data_handler(self, sock):
        print("[Server] ICMP data handler")
        packet, addr = self.icmp_socket.recvfrom(ICMP_BUFFER_SIZE)
        print(f"[Server] Received packet from {addr}")
        try:
            packet = icmp.ICMPPacket.parse(packet)
        except ValueError:
            print("Malformated packet")
            return
        print(f"[Server] Parsed packet {packet}")
        self.src = addr[0]
        self.dst_host = packet.dst_host
        self.dst_port = packet.dst_port
        if packet.icmp_type == icmp.ICMP_ECHO and packet.code == 1:
            # Close the connection with the client
            print(f"[Server] Parsed packet from client {packet}. He wants to disconnect :( ")
            self.sockets.remove(self.tcp_socket)
            self.tcp_socket.close()
            self.tcp_socket = None
        else:
            # If it's our packet, do nothing
            if not self.tcp_socket:
                print("[Server] Creating new TCP socket")
                self.tcp_socket = self.create_tcp_socket(self.dst_host, self.dst_port)
                self.sockets.append(self.tcp_socket)
            print("[Server] Sending data from client over TCP socket")
            self.tcp_socket.send(packet.data)

    def tcp_data_handler(self, sock):
        print("[Server] Received data on TCP socket")
        data = sock.recv(TCP_BUFFER_SIZE)
        packet = icmp.ICMPPacket(icmp_type=icmp.ICMP_ECHO, code=0, src_ip=self.src, dst_host=self.dst_host,
                                 dst_port=self.dst_port, data=data).create()
        print("[Server] Sending received data over ICMP connection")
        self.icmp_socket.sendto(packet, (self.src, 0))


class ProxyClient(Tunnel, threading.Thread):
    def __init__(self, proxy, sock, dst_host, dst_port):
        threading.Thread.__init__(self)
        self.proxy = proxy
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.tcp_socket = sock
        self.icmp_socket = self.create_icmp_socket()
        self.sockets = [self.tcp_socket, self.icmp_socket]

    def icmp_data_handler(self, sock):
        print("[ProxyClient] icmp_data_handler")
        data = sock.recvfrom(ICMP_BUFFER_SIZE)
        try:
            packet = icmp.ICMPPacket.parse(data[0])
        except ValueError:
            # Bad packet, malformated, not our, EOF etc..
            return
        if packet.icmp_type != icmp.ICMP_ECHO_REQUEST:
            print("[ProxyClient] Parsed ICMP packet from proxy server")
            self.tcp_socket.send(packet.data)

    def tcp_data_handler(self, sock):
        print("[ProxyClient] tcp_data_handler")
        data = sock.recv(TCP_BUFFER_SIZE)
        # Socket may be closed/timeout/EOF
        code = 0 if len(data) > 0 else 1
        print("sending packet")
        packet = icmp.ICMPPacket(icmp_type=icmp.ICMP_ECHO_REQUEST, code=code, src_ip=self.tcp_socket.getsockname(),
                                 dst_host=self.dst_host, dst_port=self.dst_port, data=data).create()
        print("[ProxyClient] sending ICMP packet to proxy server")
        self.icmp_socket.sendto(packet, (self.proxy, 1))
        if code == 1:
            print("[ProxyClient] Disconnected")
            exit()


class Proxy(ProxyClient):
    def __init__(self, proxy, listen_port, dst_host, dst_port):
        self.proxy = proxy
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.tcp_server_socket = self.create_tcp_socket(PROXY_CLIENT_LISTENING_HOST, listen_port, server=True)

    def run(self):
        print("[Proxy] Entering main loop")
        while True:
            self.tcp_server_socket.listen(5)
            sock, addr = self.tcp_server_socket.accept()
            newthread = ProxyClient(self.proxy, sock, self.dst_host, self.dst_port)
            newthread.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="ICMP tunnel for TCP traffic",
        usage="""
        client: sudo python3 tunnel.py -p <proxy_host> -lp <listen_port> -d <dst_host> -dp <dst_port>
        proxy: tunnel.py -s
        
Example:
        client: sudo python tunnel.py -p 192.168.68.118 -lp 1337 -d google.com -dp 80
        proxy: sudo python tunnel.py -s 
        nc 127.0.0.1 1337
"""
    )

    parser.add_argument("-s", "--server", action="store_true", default=False)
    parser.add_argument("-p", "--proxy_host",
                        help="Address of the proxy server")
    parser.add_argument("-lp", "--listen_port", type=int,
                        help="Port to bind for incoming TCP connections from proxy users")
    parser.add_argument("-d", "--dst_host",
                        help="dst host to connect to using TCP")
    parser.add_argument("-dp", "--dst_port", type=int,
                        help="Remote port to connect to using TCP")

    args = parser.parse_args()

    if args.server:
        tunnel = Server()
    else:
        tunnel = Proxy(
            proxy=args.proxy_host, listen_port=args.listen_port,
            dst_host=args.dst_host, dst_port=args.dst_port
        )

    tunnel.run()
