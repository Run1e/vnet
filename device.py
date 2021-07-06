import logging
from asyncio import Event, create_task, wait_for, TimeoutError, sleep, CancelledError
from collections import defaultdict
from functools import partial
from inspect import getmembers

from address import MAC
from enums import EtherType, ARPOperation
from enums import Protocol, ICMPType
from logical import *
from physical import Port
from utils import proto_handler, in_subnet

log = logging.getLogger(__name__)


ARP_CACHE_CLEAR_TIMER = 10.0


class L2Device:
	def __init__(self, name, ports):
		self.name = name

		self.mac = MAC.random()
		self.ports = [Port(partial(self.recv_frame, port_number)) for port_number in range(ports)]

		log.debug('created %s with %s', self.name, self.mac)

	def __repr__(self):
		return f'<{self.name} mac={self.mac} ports={len(self.ports)}>'

	def send_frame(self, port, frame):
		self.ports[port].send_frame(frame)

	def flood_frame(self, frame, except_port=None):
		for idx, other_port in enumerate(self.ports):
			if except_port is not None and idx == except_port:
				continue

			if not other_port.connected:
				continue

			other_port.send_frame(frame)

	def recv_frame(self, port, frame):
		if frame.dest != self.mac and frame.dest != MAC.broadcast():
			log.warning('%s received frame with wrong mac: %s', self.name, frame.dest)
			return

		self.handle_frame(port, frame)

	def handle_frame(self, port, frame):
		pass


class L3Device(L2Device):
	def __init__(self, name, ports):
		super().__init__(name, ports)

		self.interfaces = {port: dict() for port in range(ports)}  # {port {ip: interface}}
		self.rib = list()  # List[tuple]
		self.arp = dict()  # {ip: (mac, port)}
		self.arp_wait = dict()  # {ip: Event}
		self.arp_clearer = dict()  # {mac: task}

		self.proto_handlers = defaultdict(list)  # {proto: List[callable]}

		for f_name, f in getmembers(self):
			if hasattr(f, '__proto__'):
				proto = f.__proto__
				self.proto_handlers[proto].append(f)

	def add_interface(self, port, ip, cidr, gateway, wan=False, nat=False):
		ip = IP(ip)
		mask = IP.from_cidr(cidr)
		gateway = None if gateway is None else IP(gateway)

		if ip in self.interfaces:
			raise ValueError(f'Duplicate interface (IP already assigned) {ip}')

		self.interfaces[port][ip] = Interface(port, ip, mask, gateway, wan, nat)
		self.update_rib()

	def get_interface(self, ip):
		for port, port_interfaces in self.interfaces.items():
			for int_ip, interface in port_interfaces.items():
				if ip == int_ip:
					return interface

		return None

	def update_rib(self):
		self.rib = list()

		for port, port_interfaces in self.interfaces.items():
			for ip, interface in port_interfaces.items():
				if interface.gateway:
					self.add_route(Route(IP('0.0.0.0'), IP('0.0.0.0'), interface.gateway, interface.ip))

				self.add_route(Route(interface.network, interface.mask, None, interface.ip))

	def add_route(self, route):
		self.rib.append(route)

	def handle_frame(self, port, frame: Frame):
		if frame.ethertype == EtherType.IP:  # IPv4 packet
			self.recv_packet(port, frame.payload)
		elif frame.ethertype == EtherType.ARP:
			self.recv_arp(port, frame.payload)

	def recv_packet(self, port, packet: IPPacket):
		interface = self.interfaces[port].get(packet.dest, None)

		if interface is None:
			log.warning('%s: packet addressed to non-existent interface: %s', self.name, packet.dest)
			return

		self.handle_packet(interface, packet)

	def recv_arp(self, port, packet: ARPPacket):
		if packet.ptype != EtherType.IP:
			return

		# add to our own arp table first, as per the RFC
		log.debug('%s: ARP learned %s -> %s', self.name, packet.spa, packet.sha)
		self.arp[packet.spa] = (packet.sha, port)

		async def wait_and_clear_arp():
			await sleep(ARP_CACHE_CLEAR_TIMER)
			self.arp.pop(packet.spa, None)

		clearer = self.arp_clearer.get(packet.spa, None)
		if clearer is not None:
			try:
				clearer.cancel()
			except CancelledError:
				pass

		self.arp_clearer[packet.spa] = create_task(wait_and_clear_arp())

		if packet.operation == ARPOperation.REQUEST:
			interface = self.interfaces[port].get(packet.tpa, None)
			if interface is None:
				return

			reply = ARPPacket(
				ptype=EtherType.IP,
				operation=ARPOperation.REPLY,
				sha=self.mac,
				spa=interface.ip,
				tha=packet.sha,
				tpa=packet.spa,
			)

			frame = Frame(
				dest=packet.sha,
				source=self.mac,
				ethertype=EtherType.ARP,
				payload=reply
			)

			log.debug('%s: doing arp reply to %s', self.name, packet.spa)

			self.send_frame(port, frame)

		elif packet.operation == ARPOperation.REPLY:
			event = self.arp_wait.get(packet.spa, None)
			if event is not None:
				event.set()

	def arp_resolve(self, source_ip, port, dest_ip):
		packet = ARPPacket(
			ptype=EtherType.IP,
			operation=ARPOperation.REQUEST,
			sha=self.mac,
			spa=source_ip,
			tha=None,
			tpa=dest_ip,
		)

		frame = Frame(
			dest=MAC.broadcast(),
			source=self.mac,
			ethertype=EtherType.ARP,
			payload=packet,
		)

		log.debug('%s: arp request for %s on port %s', self.name, dest_ip, port)

		self.ports[port].send_frame(frame)
		self.arp_wait[dest_ip] = Event()

	def route_lookup(self, ip) -> Route:
		preferred = None
		current_specificity = None

		for route in self.rib:
			network, mask, gateway, interface = route

			# check if ip is in subnet
			# should always be true at first for the default route (gw route)
			if not in_subnet(network.value, mask.value, ip.value):
				continue

			# set this as preferred if none chosen yet
			if preferred is None or current_specificity < mask:
				preferred = route
				current_specificity = mask

		return preferred

	def route_packet(self, packet):
		route = self.route_lookup(packet.dest)

		if route is None:
			return

		self.forward_packet(route.interface, packet, next_hop=route.gateway)

	def forward_packet(self, interface, packet: IPPacket, next_hop=None):
		arp_ip = next_hop or packet.dest
		arp_entry = self.arp.get(arp_ip, None)

		if arp_entry is None:
			interface = self.get_interface(interface)
			if interface is None:
				return

			self.arp_resolve(packet.source, interface.port, arp_ip)

			async def wait_and_resend():
				event = self.arp_wait[arp_ip]

				# wait a maximum of 5 seconds for the arp reply
				# if nothing within that time, the packet is dropped
				try:
					await wait_for(event.wait(), timeout=5.0)
				except TimeoutError:
					log.warning('%s: dropping packet, no arp reply', self.name)
					return

				self.forward_packet(interface, packet, next_hop)

			create_task(wait_and_resend())
			return

		dest_mac, dest_port = arp_entry

		log.info('%s: forwarding packet for %s to %s', self.name, packet.dest, arp_ip)

		frame = Frame(dest=dest_mac, source=self.mac, ethertype=EtherType.IP, payload=packet)
		self.send_frame(dest_port, frame)

	def handle_packet(self, interface, packet: IPPacket):
		log.info('%s: received packet from %s with proto %s', self.name, packet.source, packet.protocol)

		proto = packet.protocol
		handlers = self.proto_handlers[proto]

		if proto is Protocol.ICMP:
			# special case for ICMP packets. these add some information from the IP packet
			data = ICMPPacketMeta(packet.ttl, packet.protocol, packet.source, packet.dest, packet.data)
		else:
			# for other protocols we should just give the IP packet
			data = packet.data

		for handler in handlers:
			handler(interface, data)

	def ping(self, ip: IP, icmp_id=0, icmp_seq=0, data=None):
		route = self.route_lookup(ip)

		if route is None:
			return

		packet = IPPacket(
			dest=ip,
			source=route.interface,
			protocol=Protocol.ICMP,
			data=ICMPPacket(ICMPType.ECHO, 0, dict(icmp_id=icmp_id, icmp_seq=icmp_seq), data),
		)

		self.forward_packet(route.interface, packet, next_hop=route.gateway)

	@proto_handler(Protocol.ICMP)
	def handle_icmp(self, interface, icmp: ICMPPacketMeta):
		if icmp.icmp.type == ICMPType.ECHO:
			icmp_packet: ICMPPacket = icmp.icmp

			icmp_packet.type = ICMPType.ECHO_REPLY

			ip_packet = IPPacket(
				dest=icmp.source,
				source=icmp.dest,
				protocol=Protocol.ICMP,
				data=icmp_packet,
				ttl=8,
			)

			self.route_packet(ip_packet)

		elif icmp.icmp.type == ICMPType.ECHO_REPLY:
			header = icmp.icmp.header

			log.warning(
				'%s: ICMP ECHO_REPLY on interface %s from %s icmp_id=%s icmp_seq=%s',
				self.name, interface.ip, icmp.source,
				header['icmp_id'], header['icmp_seq']
			)
