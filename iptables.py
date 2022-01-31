from ipaddress import IPv4Address, ip_address
import ipaddress
from typing import Optional
from iptc import Chain, Rule, Table
from abc import ABC

from consts import DROP_TABLE, ICMP_PROTOCOL, INPUT_TABLE, LOOPBACK_DEVICE, LOOPBACK_IP, OUTPUT_TABLE, TCP_PROTOCOL
    
class IPTablesRule(ABC):
	def __init__(self):
		self.rule: Rule  = self._create_rule()
		self.chain: Rule = self._get_chain()

	def _create_rule(self) -> Rule:
		raise NotImplementedError

	def _get_chain(self) -> Chain:
		raise NotImplementedError

	def __enter__(self):
		self.chain.insert_rule(self.rule)

	def __exit__(self):	
		self.chain.delete_rule(self.rule)



class IPTablesICMPRule(IPTablesRule):
	"""
	Class for IPTable rules that drops ICMP packets
	"""
	def __init__(self, ip: IPv4Address):
		self.ip = ip
		super().__init__(ip=ip)

	def _create_rule(self) -> Rule:
		rule = Rule()
		rule.protocol = ICMP_PROTOCOL
		rule.create_target(DROP_TABLE)
		rule.dst = self.ip
		return rule

	def _get_chain(self) -> Chain:
		return Chain(Table(Table.FILTER), OUTPUT_TABLE)


class IPTablesLoopbackRule(IPTablesRule):
	"""
	Class for IPTable rules that drop TCP packets on loopback device
	"""
	def __init__(self, port: int, is_server: bool):
		self.port = port
		self.is_server = is_server
		super().__init__()

	def _create_rule(self) -> Rule:
		"""
		Create rule that drops TCP packets on loopback device from/to specific TCP port
		"""
		rule = Rule()
		rule.src = LOOPBACK_IP
		rule.dst = LOOPBACK_IP
		rule.in_interface = LOOPBACK_DEVICE
		rule.protocol = TCP_PROTOCOL
		rule.create_target(DROP_TABLE)
		match = rule.create_match(TCP_PROTOCOL)

		if self.is_server:
			match.sport = str(self.port)
		else:
			match.dport = str(self.port)
		
		return rule

	def _get_chain(self) -> Chain:
		return Chain(Table(Table.FILTER), INPUT_TABLE)
	