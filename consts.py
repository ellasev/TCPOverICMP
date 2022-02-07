from ipaddress import IPv4Address
import ipaddress

LOOPBACK_IP = "127.0.0.1"
LOOPBACK_DEVICE = "lo"

TCP_PROTOCOL = "tcp"
ICMP_PROTOCOL = "icmp"

OUTPUT_TABLE = "OUTPUT"
DROP_TABLE = "DROP"
INPUT_TABLE = "INPUT"

ICMP_BUFFER_SIZE = 4096
TCP_BUFFER_SIZE = 2048
ICMP_ID = 2610
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8