from iptc import Chain, Rule, Table
from abc import ABC

from consts import DROP_TABLE, ICMP_PROTOCOL, INPUT_TABLE, LOOPBACK_DEVICE, LOOPBACK_IP, OUTPUT_TABLE, TCP_PROTOCOL
    

class IPTablesRule(ABC):
	"""
	Abstract IPTables rule to inherit and implement your IPTables rule form.
	"""
	def __init__(self):
		"""
		Define rule and chain
		"""
		self.rule: Rule  = self._create_rule()
		self.chain: Rule = self._get_chain()

	def _create_rule(self) -> Rule:
		"""
		Function that is called from main and must be implemented by inherting classes. 
		defines the rule 
		"""
		raise NotImplementedError

	def _get_chain(self) -> Chain:
		"""
		Function that is called from main and must be implemented by inherting classes. 
		defines the chain 
		"""
		raise NotImplementedError

	def apply(self):
		"""
		Add the rule to the list of rules that are enforced 
		"""
		self.chain.insert_rule(self.rule)

	def delete(self):	
		"""
		Remove the rule from the list of rules that are enforced 
		"""
		self.chain.delete_rule(self.rule)

class IPTableManager():
	"""
	Manage the iptables rule, make sure to clean them up when exiting
	"""
	def __init__(self):
		"""
		Initialize.
		Initialize rules list
		"""
		self.rules_list = []
	
	def add_rule(self, rule:IPTablesRule):
		"""
		Add a rule to the IPtables applied rules and also to the classes list of applied rules

		:param rule - rule to add
		"""
		rule = Rule()
		rule.protocol = ICMP_PROTOCOL
		rule.create_target(DROP_TABLE)
		self.rules_list.append(rule)
		rule.apply()
	
	def __enter__(self):

		"""
		Constructor 

		"""
		return self

	def __exit__(self, type, value, traceback):	

		"""
		Destructor
		Remove that appear in our list of rules from systems applied rules.
		"""
		for rule in self.rules_list:
			rule.delete()

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
		Defines the rule.
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

		"""
		defines the chain 
		"""
		return Chain(Table(Table.FILTER), INPUT_TABLE)


class IPTablesICMPRule(IPTablesRule):
	"""
	Class for IPTable rules that drops ICMP packets
	"""
	def __init__(self, ip: str):
		self.ip = ip
		super().__init__()

	def _create_rule(self) -> Rule:
		""" 
		Defines the rule.
		"""
		rule = Rule()
		rule.protocol = ICMP_PROTOCOL
		rule.create_target(DROP_TABLE)
		rule.src = self.ip
		return rule

	def _get_chain(self) -> Chain:

		"""
		defines the chain 
		"""
		return Chain(Table(Table.FILTER), OUTPUT_TABLE)
