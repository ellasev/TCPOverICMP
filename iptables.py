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

	def apply(self):
		self.chain.insert_rule(self.rule)

	def delete(self):	
		self.chain.delete_rule(self.rule)

class IPTableManager():
	def __init__(self):
		self.rules_list = []
	
	def add_rule(self, rule:IPTablesRule):
		self.rules_list.append(rule)
		rule.apply()
	
	def __enter__(self):
		return self

	def __exit__(self, type, value, traceback):	
		for rule in self.rules_list:
			rule.delete()


class IPTablesICMPRule(IPTablesRule):
	"""
	Class for IPTable rules that drops ICMP packets
	"""
	def __init__(self, ip: str):
		self.ip = ip
		super().__init__()

	def _create_rule(self) -> Rule:
		rule = Rule()
		rule.protocol = ICMP_PROTOCOL
		rule.create_target(DROP_TABLE)
		#rule.src = self.ip
		return rule

	def _get_chain(self) -> Chain:
		return Chain(Table(Table.FILTER), OUTPUT_TABLE)
