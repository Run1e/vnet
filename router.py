import logging

from device import L3Device
from enums import Protocol
from logical import ICMPPacket, IP, IPPacket

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
		interface = self.get_interface(packet.dest)

		if interface is not None:
			# this packet is addressed to this router

			identifier = (packet.protocol, packet.source, self.get_packet_nat_identifier(packet))
			dest = self.nat.get(identifier, None)
			if dest is None:
				# no nat match found, this packet is for the router
				self.handle_packet(interface, packet)
			else:
				# nat match found, this packet is an inbound NAT packet
				packet.dest = dest
				self.forward_packet(packet)

		else:
			# this packet is *not* addressed to this router

			# check if we have an interface on this port
			# this will be default gw in that case
			interface = None
			for interface in self.interfaces.values():
				if interface.port == port:
					break

			if interface is None or interface.ip not in self.nat_interfaces:
				return  # no interface configured on this port, or this interface is not an interface with NAT enabled

			route = self.find_route(packet.dest)
			if route is None:
				return  # no valid route

			# add entry to nat table
			identifier = (packet.protocol, packet.dest, self.get_packet_nat_identifier(packet))
			self.nat[identifier] = packet.source

			packet.source = route.interface
			self.forward_packet(packet, route)
