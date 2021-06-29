import asyncio
import logging

from device import L3Device
from logical import IPAddress, IPPacket
from physical import Cable
from switch import Switch
from enums import Protocol
from utils import proto_handler

logging.basicConfig(format='[%(name)s] %(message)s', level=logging.DEBUG)
log = logging.getLogger()


class L3Node(L3Device):
	def __init__(self, name):
		super().__init__(name=name, ports=1)

	def asd(self, interface, packet: IPPacket):
		print(interface.ip, packet.source, packet.data)

		if self.name == 'a':
			packet = IPPacket(dest=IPAddress('192.168.1.20'), source=packet.dest, data='hi from a!')
		elif self.name == 'b':
			packet = IPPacket(dest=IPAddress('192.168.1.30'), source=packet.dest, data='hi from b!')
		elif self.name == 'c':
			packet = IPPacket(dest=IPAddress('192.168.1.10'), source=packet.dest, data='hi from c!')
		self.send_packet(packet)

	@proto_handler(Protocol.ICMP)
	def handle_icmp(self, interface, packet):
		print('icmp', packet)


a = L3Node('a')
a.add_interface(0, '192.168.1.10', 24, '192.168.1.1')

b = L3Node('b')
b.add_interface(0, '192.168.1.20', 24, '192.168.1.1')

c = L3Node('c')
c.add_interface(0, '192.168.1.30', 24, '192.168.1.1')

s1 = Switch('sw1', ports=4)
s2 = Switch('sw2', ports=4)
s3 = Switch('sw3', ports=4)


async def main():
	Cable(a.ports[0], s1.ports[0])
	Cable(b.ports[0], s2.ports[0])
	Cable(c.ports[0], s3.ports[0])
	Cable(s1.ports[3], s2.ports[3])
	Cable(s2.ports[2], s3.ports[3])
	# Cable(s1.ports[2], s3.ports[2])

	packet = IPPacket(
		IPAddress('192.168.1.20'),
		IPAddress('192.168.1.10'),
		Protocol.ICMP,
		'ping!',
	)

	a.send_packet(packet)


if __name__ == '__main__':
	loop = asyncio.get_event_loop()
	loop.run_until_complete(main())
	loop.run_forever()
