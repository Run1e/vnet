from collections import namedtuple

from address import IP

Route = namedtuple('Route', 'destination netmask gateway interface')
Forwarding = namedtuple('Forwarding', 'network mask next_hop')


class Frame:
	def __init__(self, dest, source, ethertype, payload):
		self.dest = dest
		self.source = source
		self.ethertype = ethertype
		self.payload = payload

	def __repr__(self):
		return f'<Frame dest={self.dest} source={self.source}>'


class IPPacket:
	# also called an IP datagram in some cases
	def __init__(self, dest, source, protocol, data, ttl=8):
		self.dest = dest
		self.source = source
		self.protocol = protocol
		self.data = data
		self.ttl = ttl


class ICMPPacket:
	def __init__(self, type, code, header, data):
		self.type = type
		self.code = code
		self.header = header
		self.data = data


class ICMPPacketMeta:
	def __init__(self, ttl, protocol, source, dest, icmp):
		self.ttl = ttl
		self.protocol = protocol
		self.source = source
		self.dest = dest
		self.icmp: ICMPPacket = icmp


class TCPSegment:
	def __init__(self, source_port, dest_port, seq_number, ack_number, data):
		self.source_port = source_port
		self.dest_port = dest_port
		self.seq_number = seq_number
		self.ack_number = ack_number
		self.data = data


class ARPPacket:
	def __init__(self, ptype, operation, sha, spa, tha, tpa):
		self.ptype = ptype
		self.operation = operation
		self.sha = sha
		self.spa = spa
		self.tha = tha
		self.tpa = tpa


class Interface:
	def __init__(self, port, ip, mask, gateway, wan, nat):
		self.port = port
		self.ip = ip
		self.mask = mask
		self.network = IP(ip.value & mask.value)
		self.gateway = gateway
		self.wan = wan
		self.nat = nat

	def __repr__(self):
		return f'<Interface ip={self.ip}>'
