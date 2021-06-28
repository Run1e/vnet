import logging
from functools import partial

from randmac import RandMac

from physical import Port


class Device:
	def __init__(self, name, ports):
		self.name = name

		self.mac = str(RandMac())
		self.ports = [Port(partial(self.recv, port_number)) for port_number in range(ports)]

	def __repr__(self):
		return f'<{self.name} mac={self.mac} ports={len(self.ports)}>'

	def send(self, port, frame):
		self.ports[port].send(frame)

	def recv(self, port, frame):
		pass
