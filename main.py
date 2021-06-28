import logging

from randmac import RandMac

from device import Device
from logical import Frame
from physical import Cable
from switch import Switch

logging.basicConfig(format='[%(name)s] %(message)s', level=logging.DEBUG)
log = logging.getLogger()

MTU = 1500


class Node(Device):
	def __init__(self, name):
		super().__init__(name=name, ports=1)

		self.mac = str(RandMac())

	def recv(self, port, frame):
		if frame.dest != self.mac:
			log.info('%s received frame with wrong mac: %s', self.mac, frame.dest)
			return

		log.info('%s received payload: %s', self.name, frame.payload)
		if frame.source == a.mac:
			self.send(0, Frame(a.mac, self.mac, 0, 'hello from b!'))
		#if frame.source == b.mac:
		#	self.send(0, Frame(a.mac, self.mac, 0, 'hello from c!'))


a = Node('a')
b = Node('b')
c = Node('c')

for x in [a, b, c]:
	print(x.mac)

s1 = Switch('sw1', ports=4)

Cable(a.ports[0], s1.ports[0])
Cable(b.ports[0], s1.ports[1])

while True:
	x = input('data: ')
	a.send(0, Frame(b.mac, a.mac, 0, x))

	log.info('s1 cam: %s', s1.cam)
