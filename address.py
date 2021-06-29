from random import randint

import utils


class BaseAddress:
	def __hash__(self):
		return hash(self.value)

	def __eq__(self, other):
		if isinstance(other, BaseAddress):
			other = other.value
		return self.value == other

	def __ne__(self, other):
		return not self.__eq__(other)


class MACAddress(BaseAddress):
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


class IPAddress(BaseAddress):
	def __init__(self, ip):
		if isinstance(ip, str):
			self.value = utils.ip_to_bin(ip)
		elif isinstance(ip, int):
			self.value = ip
		else:
			raise ValueError('Not a valid ip string or value')

	@classmethod
	def from_cidr(cls, cidr):
		return cls(utils.mask_from_cidr(cidr))

	def in_subnet(self, network, mask):
		return utils.in_subnet(network, mask, self.value)

	def __repr__(self):
		return f'<IP {utils.bin_to_ip(self.value)}>'
