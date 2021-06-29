import logging
from collections import defaultdict

from device import L3Device
from logical import IPPacket, Interface, ICMPPacket, IP
from enums import Protocol

log = logging.getLogger(__name__)


class Router(L3Device):
	def __init__(self, name, ports):
		super().__init__(name, ports)

		self.nat = dict()  # {external_ip: {hash: dest_ip}}
		self.nat_interfaces = list()

	def add_nat(self, ip):
		self.nat_interfaces.append(IP(ip))

	def get_packet_nat_identifier(self, packet: IPPacket):
		if packet.protocol is Protocol.ICMP:
			data: ICMPPacket = packet.data
			return data.header['icmp_id']

	def recv_packet(self, port, packet: IPPacket):
		interface = None
		for interface in self.interfaces.values():
			if interface.port == port:
				break

		if interface is None:
			return  # no interface configured on this port?

		if not self.handle_packet(interface, packet):
			self.handle_routing(interface, packet)

	def handle_routing(self, interface, packet: IPPacket):
		# here we need to find outgoing interface
		# add hash to nat table
		# change values in the IP header
		# and send to that outgoing interface

		if interface.ip in self.nat_interfaces:
			self.handle_outgoing_nat(interface, packet)
		else:  # should probably be some predicate here
			self.handle_incoming_nat(interface, packet)

	def handle_outgoing_nat(self, interface, packet):
		route = self.find_route(packet.dest)

		if route is None:
			return  # no valid route

		# find nat identifier for this packet
		# this is done in a dumb way but it's fine for this limited purpose
		# it should really be "bit-aligned"
		identifier = (packet.protocol, packet.dest, self.get_packet_nat_identifier(packet))

		# add entry to nat table
		self.nat[identifier] = packet.source

		#log.info('%s: outgoing nat source %s changed to %s on %s', self.name, packet.source, route.interface, route)

		# change packet source to the WAN interface ip
		packet.source = route.interface

		self.forward_packet(packet, route)

	def handle_incoming_nat(self, interface, packet):
		identifier = (packet.protocol, packet.source, self.get_packet_nat_identifier(packet))

		dest = self.nat.get(identifier, None)
		if dest is None:
			return  # can't find entry in nat table

		#log.info('%s: incoming nat dest %s changed to %s', self.name, packet.dest, dest)

		packet.dest = dest

		self.forward_packet(packet)
