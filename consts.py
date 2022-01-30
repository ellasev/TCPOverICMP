from ipaddress import IPv4Address
import ipaddress


LOOPBACK_IP = ipaddress.ip_address("127.0.0.1")
LOOPBACK_DEVICE = "lo"

TCP_PROTOCOL = "tcp"
ICMP_PROTOCOL = "icmp"

OUTPUT_TABLE = "output"
DROP_TABLE = "drop"
INPUT_TABLE = "input"