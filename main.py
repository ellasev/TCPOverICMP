import argparse
import traceback

from proxy_server import ProxyServer
from proxy_client import ProxyClient

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="ICMP tunnel for TCP traffic",
        usage=
        """
        client: sudo python3 tunnel.py -p <proxy_host> -lp <listen_port> -dp <dst_port>
        proxy: tunnel.py -s
            
        Example:
            client: sudo python tunnel.py -p 1.2.3.4 -lp 1337 -dp 22
            proxy: sudo python tunnel.py -s 
        """
    )

    parser.add_argument("-s", "--server", action="store_true", default=False)
    parser.add_argument("-p", "--proxy_host",
                        help="Address of the proxy server")
    parser.add_argument("-lp", "--listen_port", type=int,
                        help="Port to bind for incoming TCP connections from proxy users")

    args = parser.parse_args()

    
    try:
        if args.server:
            tunnel = ProxyServer()
        else:
            tunnel = ProxyClient(
                proxy_server_host=args.proxy_host, listen_port=args.listen_port)

        tunnel.run(args.server)

    except:
        print("Main exited with exception: ")
        print(traceback.format_exc())