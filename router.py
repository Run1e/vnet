import logging

from device import L3Device
from enums import Protocol
from logical import ICMPPacket, IP, IPPacket, Forwarding
from utils import in_subnet

log = logging.getLogger(__name__)


class Router(L3Device):
	def __init__(self, name, ports):
		super().__init__(name, ports)

		self.fib = dict()  # {(network, mask): next_hop}
		self.nat = dict()  # {external_ip: {hash: dest_ip}}

	def get_packet_nat_identifier(self, packet: IPPacket):
		if packet.protocol is Protocol.ICMP:
			data: ICMPPacket = packet.data
			return data.header['icmp_id']

	def update_rib(self):
		super().update_rib()

		# for routers we also need to make sure a nat entry exist for WAN interfaces
		for port, port_interfaces in self.interfaces.items():
			for ip, interface in port_interfaces.items():
				if interface.wan and interface.ip not in self.nat:
					self.nat[interface.ip] = dict()

	def translate_inbound_nat(self, interface, packet):
		nat_table = self.nat.get(interface.ip, None)
		if nat_table is None:
			return None

		identifier = (packet.protocol, packet.source, self.get_packet_nat_identifier(packet))
		return nat_table.get(identifier, None)

	def addressed_to_router(self, interface, packet):
		"""
		this packet is not addressed to an interface on the router.
		this means:
		1. it's on the global interface and it's an external packet for the router
		2. it's on the global interface and the packet should be natted to an internal node
		"""

		# if there's an inbound entry for this packet we need to rewrite the destination
		# and continue routing it
		dest = self.translate_inbound_nat(interface, packet)

		if dest is None:
			# if there's no NAT table for this the incoming interface,
			# we can safely assume this packet is for the router itself
			self.handle_packet(interface, packet)
		else:
			log.info('%s: NAT translating inbound packet dest from %s to %s', self.name, packet.dest, dest)
			packet.dest = dest
			self.route_packet(packet)

	def forwarding_lookup(self, ip):
		preferred = None
		current_specificity = None

		for forwarding in self.fib:
			network, mask, next_hop = forwarding

			# check if ip is in subnet
			# should always be true at first for the default route (gw route)
			if not in_subnet(network.value, mask.value, ip.value):
				continue

			# set this as preferred if none chosen yet
			if preferred is None or current_specificity < mask:
				preferred = forwarding
				current_specificity = mask

		return preferred

	def addressed_to_other(self, interface, packet):
		route = self.route_lookup(packet.dest)

		if route is None:
			return  # no valid route for the destination

		egress = self.get_interface(route.interface)

		if not egress.wan:
			# if the egress interface is not a WAN interface we can simply forward this packet
			self.forward_packet(route.interface, packet)
			return

		# if not addressed to us, but incoming interface is not a nat interface, return
		if not interface.nat:
			return

		nat_table = self.nat.get(egress.ip, None)
		if nat_table is None:
			return  # this shouldn't happen unless misconfiguration

		# add entry to nat table
		identifier = (packet.protocol, packet.dest, self.get_packet_nat_identifier(packet))
		nat_table[identifier] = packet.source

		log.info('%s: NAT translating outbound packet source from %s to %s', self.name, packet.source, egress.ip)

		packet.source = route.interface
		self.forward_packet(route.interface, packet, route.gateway)

	def recv_packet(self, port, packet: IPPacket):
		interface = self.get_interface(packet.dest)

		if interface is not None:
			self.addressed_to_router(interface, packet)
		else:
			# this packet is *not* addressed to this router

			# check if we have an interface on this port
			# this will be default gw in that case
			# NOTE: this is probably a dumb way of doing this
			# but I'm not sure how to otherwise do it
			interface = None
			for interface in self.interfaces[port].values():
				if interface.port == port:
					break

			if interface is None:
				return  # no interface configured on this port

			self.addressed_to_other(interface, packet)
