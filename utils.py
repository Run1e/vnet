IPv4_SHIFTS = [24, 16, 8, 0]
IPv4_MAX = 2 ** 32 - 1
MAC_SHIFTS = [40, 32, 24, 16, 8, 0]


def proto_handler(proto):
	def wrapper(func):
		func.__proto__ = proto
		return func

	return wrapper


def mac_to_bin(mac: str):
	octets = [int(octet, 16) for octet in mac.split(':')]

	bits = 0

	for octet, shift in zip(octets, MAC_SHIFTS):
		bits |= octet << shift

	return bits


def bin_to_mac(bits: int):
	parts = list()
	for shift in MAC_SHIFTS:
		h = hex(bits >> shift & 255)[2:]
		if len(h) < 2:
			h = '0' + h
		parts.append(h)

	return ':'.join(parts)


def ip_to_bin(ip: str):
	octets = [int(octet) for octet in ip.split('.')]

	bits = 0

	for octet, shift in zip(octets, IPv4_SHIFTS):
		bits |= octet << shift

	return bits


def bin_to_ip(bits: int):
	return '.'.join(str(bits >> shift & 255) for shift in IPv4_SHIFTS)


def in_subnet(network, mask, ip):
	return network <= ip <= network | IPv4_MAX - mask


def mask_from_cidr(cidr):
	return 2 ** cidr - 1 << (32 - cidr)
