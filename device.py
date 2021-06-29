import logging

from asyncio import Event, create_task
from collections import defaultdict
from functools import partial

from enums import EtherType, ARPOperation
from address import IPAddress
from address import MACAddress
from logical import Frame, IPPacket, Interface, ARPPacket
from physical import Port
from enums import Protocol

log = logging.getLogger(__name__)


class L2Device:
	def __init__(self, name, ports):
		self.name = name

		self.mac = MACAddress.random()
		self.ports = [Port(partial(self.recv_frame, port_number)) for port_number in range(ports)]

	def __repr__(self):
		return f'<{self.name} mac={self.mac} ports={len(self.ports)}>'

	def send_frame(self, port, frame):
		self.ports[port].send_frame(frame)

	def flood_frame(self, frame, except_port=None):
		for idx, other_port in enumerate(self.ports):
			if except_port is not None and idx == except_port:
				continue

			other_port.send_frame(frame)

	def recv_frame(self, port, frame):
		if frame.dest != self.mac and frame.dest != MACAddress.broadcast():
			log.info('%s received frame with wrong mac: %s', self.mac, frame.dest)
			return

		self.handle_frame(port, frame)

	def handle_frame(self, port, frame):
		pass


class L3Device(L2Device):
	def __init__(self, name, ports):
		super().__init__(name, ports)

		self.interfaces = dict()  # {ip: interface}
		self.arp = dict()  # {ip: (mac, port)}
		self.arp_wait = dict()  # {ip: Event}

		self.proto_handlers = defaultdict(list)  # {proto: List[callable]}

		from inspect import getmembers, ismethod
		for f_name, f in getmembers(self):
			if hasattr(f, '__proto__'):
				proto = f.__proto__
				self.proto_handlers[proto].append(f)

	def add_interface(self, port, ip, cidr, gateway):
		ip = IPAddress(ip)
		mask = IPAddress.from_cidr(cidr)
		gateway = IPAddress(gateway)

		if ip in self.interfaces:
			raise ValueError(f'Duplicate interface (IP already assigned) {ip}')

		self.interfaces[ip] = Interface(port, ip, mask, gateway)

	def handle_frame(self, port, frame: Frame):
		if frame.ethertype == EtherType.IP:  # IPv4 packet
			self.recv_packet(port, frame.payload)
		elif frame.ethertype == EtherType.ARP:
			self.recv_arp(port, frame.payload)

	def recv_packet(self, port, packet: IPPacket):
		interface = self.interfaces.get(packet.dest, None)

		if interface is None or interface.port != port:
			return

		self.handle_packet(interface, packet)

	def recv_arp(self, port, packet: ARPPacket):
		if packet.ptype != EtherType.IP:
			return

		# add to our own arp table first, as per the RFC
		log.info('%s arp learn %s -> %s', self.name, packet.spa, packet.sha)
		self.arp[packet.spa] = (packet.sha, port)

		if packet.operation == ARPOperation.REQUEST:
			interface = self.interfaces.get(packet.tpa, None)
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

			self.send_frame(port, frame)

		elif packet.operation == ARPOperation.REPLY:
			event = self.arp_wait.get(packet.spa, None)
			if event is not None:
				event.set()

	def arp_request(self, source_ip, port, dest_ip):
		packet = ARPPacket(
			ptype=EtherType.IP,
			operation=ARPOperation.REQUEST,
			sha=self.mac,
			spa=source_ip,
			tha=None,
			tpa=dest_ip,
		)

		frame = Frame(
			dest=MACAddress.broadcast(),
			source=self.mac,
			ethertype=EtherType.ARP,
			payload=packet,
		)

		self.ports[port].send_frame(frame)
		self.arp_wait[dest_ip] = Event()

	def send_packet(self, packet: IPPacket):
		arp_entry = self.arp.get(packet.dest, None)

		if arp_entry is None:
			interface = self.interfaces[packet.source]
			self.arp_request(packet.source, interface.port, packet.dest)

			async def wait_and_resend():
				event = self.arp_wait[packet.dest]
				await event.wait()
				self.send_packet(packet)

			create_task(wait_and_resend())
			return

		dest_mac, dest_port = arp_entry

		frame = Frame(dest=dest_mac, source=self.mac, ethertype=EtherType.IP, payload=packet)
		self.send_frame(dest_port, frame)

	def handle_packet(self, interface, packet: IPPacket):
		proto = packet.protocol
		handlers = self.proto_handlers[proto]

		if proto is Protocol.ICMP:
			# special case for ICMP
			# ICMP is processed differently from other IP protocols.
			# because of this, we send the entire IP packet to the handler.
			# the alternative would be to have more ICMP logic inside this general handler, which I don't want
			data = packet
		else:
			# for other protocols we should just give the IP packet
			data = packet.data

		for handler in handlers:
			handler(interface, data)
