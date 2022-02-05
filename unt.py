import argparse
import struct

import select
import socket
import threading
import traceback
from scapy.all import *

ICMP_BUFFER_SIZE = 1024
TCP_BUFFER_SIZE = 1024
ICMP_ID = 2610
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

class Tunnel(threading.Thread):
    def icmp_data_handler(self, sock):
        print(f"[Tunnel] icmp_data_handler: {sock.recv()}")

    def tcp_data_handler(self, sock):
        print(f"[Tunnel] tcp_data_handler: {sock.recv()}")

    def run(self):
        print("[Tunnel] main loop")
        while True:
            read, _, _ = select.select(self.sockets, [], [])
            for sock in read:
                if sock.proto == socket.IPPROTO_ICMP:
                    self.icmp_data_handler(sock)
                else:
                    self.tcp_data_handler(sock)

class ParsedPacket():
    def __init__(self, icmp_type, src_host):
        self.icmp_type = icmp_type
        self.src_host = src_host
        self.remote_dst_host = None
        self.remote_dst_port = None
        self.data = None


class IcmpServer():
    @staticmethod
    def create_icmp_socket():
        print("[IcmpServer] Creating ICMP socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        return sock

    @staticmethod
    def parse_icmp_packet(data):
        packet = IP(data)
        assert packet[ICMP].id == ICMP_ID, "Wrong ICMP ID"

        parsed_packet = ParsedPacket(icmp_type = packet[ICMP].type, src_host = packet[IP].src)
        struct_size = struct.calcsize("4sH")
        payload = bytes(packet[ICMP].payload)

        parsed_packet.remote_dst_host, parsed_packet.remote_dst_port = struct.unpack("4sH", payload[:struct_size])
        parsed_packet.data = payload[struct_size:]
        parsed_packet.remote_dst_host = socket.inet_ntoa(parsed_packet.remote_dst_host)

        return parsed_packet

    @staticmethod
    def build_icmp_packet(icmp_type, dst_host, remote_dst_host='0.0.0.0', remote_dst_port=0, data=''):
        payload = struct.pack("4sH", socket.inet_aton(remote_dst_host), remote_dst_port) + data
        return IP(dst = dst_host) / ICMP(id=ICMP_ID, type=icmp_type, seq=1) / payload
        


class ProxyServer(Tunnel):
    def __init__(self):
        self.proxy_icmp_socket = IcmpServer.create_icmp_socket()
        self.sockets = [self.proxy_icmp_socket]
        self.tcp_socket = None

        Tunnel.__init__(self)

    def _create_tcp_socket(self, remote_dst_host, remote_dst_port):
        print("[ProxyServer] Creating new TCP socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((remote_dst_host, remote_dst_port))

        return sock

    def _close_conenction(self):
        print(f"[ProxyServer] Parsed packet from client {packet}. He wants to disconnect :( ")
        self.sockets.remove(self.tcp_socket)
        self.tcp_socket.close()
        self.tcp_socket = None

    def icmp_data_handler(self, sock):
        print("[ProxyServer] ICMP data handler")
        assert sock == self.proxy_icmp_socket, "WTF"

        try:
            packet = IcmpServer.parse_icmp_packet(self.proxy_icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])
            print(f"[ProxyServer] Parsed packet {packet}")

            self.proxy_client_host = packet.src_host
            self.remote_dst_host = packet.remote_dst_host
            self.remote_dst_port = packet.remote_dst_port
            if packet.icmp_type == ICMP_ECHO_REQUEST:
                if len(packet.data) == 0:
                    self._close_conenction()
                else:
                    if not self.tcp_socket:
                        print(self.remote_dst_host, self.remote_dst_port)
                        self.tcp_socket = self._create_tcp_socket(self.remote_dst_host, self.remote_dst_port)
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

        data = self.tcp_socket.recv(TCP_BUFFER_SIZE)

        print("[ProxyClientThread] Building ICMP packet")
        packet = IcmpServer.build_icmp_packet(icmp_type=ICMP_ECHO_REPLY, dst_host=self.proxy_client_host, data=data)

        print("[ProxyServer] Sending received data over ICMP connection")
        send(packet)

class ProxyClientThread(Tunnel):
    def __init__(self, proxy_server_host, tcp_socket, proxy_icmp_socket, remote_server_host, remote_server_port):
        self.proxy_server_host = proxy_server_host
        self.tcp_socket = tcp_socket
        self.proxy_icmp_socket = proxy_icmp_socket
        self.remote_server_host = remote_server_host
        self.remote_server_port = remote_server_port
        self.sockets = [tcp_socket, proxy_icmp_socket]

        Tunnel.__init__(self)

    def icmp_data_handler(self, sock):
        print("[ProxyClientThread] icmp_data_handler")
        assert sock == self.proxy_icmp_socket, "WTF"
        try:
            packet = IcmpServer.parse_icmp_packet(self.proxy_icmp_socket.recvfrom(ICMP_BUFFER_SIZE)[0])

            if packet.icmp_type == ICMP_ECHO_REPLY:
                print("[ProxyClientThread] Parsed ICMP packet from proxy server")
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
            exit()
        

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
        while True:
            self.proxy_tcp_socket.listen(5)
            sock, addr = self.proxy_tcp_socket.accept()
            print("[ProxyClient] New connection!")
            new_thread = ProxyClientThread(self.proxy_server_host, sock, self.proxy_icmp_socket, self.remote_server_host, self.remote_server_port)
            new_thread.start()

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
        tunnel = ProxyServer()
    else:
        tunnel = ProxyClient(
            proxy_server_host=args.proxy_host, listen_port=args.listen_port,
            remote_server_host=args.dst_host, remote_server_port=args.dst_port
        )

    tunnel.run()
