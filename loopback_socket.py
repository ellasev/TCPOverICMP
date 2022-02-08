from scapy.all import * 

from iptables import IPTableManager, IPTablesLoopbackRule
from consts import TCP_BUFFER_SIZE


class LoopbackSocket():
	"""
	Loopback Raw Layer3 socket to sniff and write 
	packets from or to the ICMP tunnel.
	"""
	def __init__(self, listen_port, is_server):
		"""
		Initialize socket.

		:param listen_port - TCP port to listen to.
		:param is_server - Whether we should sniff incoming or outgoing packets to the listen_port
		"""
		self.listen_port = listen_port
		self.is_server = is_server

		print(f"[LoopbackSocket] Creating Raw TCP socket on loopback: {'127.0.0.1', listen_port}")
		self.socket = L3RawSocket(iface='lo')

		self.loopback_iptables_rule = IPTablesLoopbackRule(port=listen_port, is_server=False)
		self.loopback_iptables_rule.apply()


	def __exit__(self, type, value, traceback):	
		self.loopback_iptables_rule.delete()

	def recv(self):
		"""
		Receive Packet from raw socker 

		@returns the packet from the TCP layer and up
		"""
		packet = self.socket.recv(TCP_BUFFER_SIZE)
		if TCP in packet:
			if getattr(packet[TCP], "sport" if self.is_server else "dport") == self.listen_port and (packet[IP].src == '127.0.0.1' or packet[IP].dst == '127.0.0.1'):
				return raw(packet[TCP])

	def send(self, partial_packet):
		"""
		Send packet to raw socket 
		
		:param partial_packet - packet from the TCP layer and up
		"""
		packet = IP(dst='127.0.0.1') / TCP(partial_packet)
		del packet[TCP].chksum

		self.socket.send(packet)