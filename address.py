from random import randint

import utils


class BaseAddress:
	def __hash__(self):
		return hash(self.value)

	def __eq__(self, other):
		return self.value == other

	def __ne__(self, other):
		return not self.__eq__(other)

	def __lt__(self, other):
		return self.value < other.value

	def __le__(self, other):
		return self.value <= other.value

	def __gt__(self, other):
		return self.value > other.value

	def __ge__(self, other):
		return self.value >= other.value


class MAC(BaseAddress):
	def __init__(self, mac):
		if isinstance(mac, str):
			self.value = utils.mac_to_bin(mac)
		elif isinstance(mac, int):
			self.value = mac
		else:
			raise ValueError('Not a valid mac string or value')

	@classmethod
	def broadcast(cls):
		return cls(2 ** 48 - 1)

	@classmethod
	def random(cls):
		return cls(randint(0, 2 ** 48 - 2))

	def __repr__(self):
		return f'<MAC {utils.bin_to_mac(self.value)}>'


class IP(BaseAddress):
	def __init__(self, ip):
		if isinstance(ip, str):
			self.value = utils.ip_to_bin(ip)
		elif isinstance(ip, int):
			self.value = ip
		else:
			raise ValueError('Not a valid ip string or value')

	@classmethod
	def from_cidr(cls, cidr):
		return cls(2 ** cidr - 1 << (32 - cidr))

	def __repr__(self):
		return f'<IP {utils.bin_to_ip(self.value)}>'
