import asyncio
import logging

from pprint import pprint
from device import L3Device
from logical import *
from physical import Cable
from switch import Switch
from router import Router

logging.basicConfig(format='[%(name)s] %(message)s', level=logging.DEBUG)
log = logging.getLogger()

n1 = L3Device('n1', 1)
n1.add_interface(0, '192.168.1.10', 24, '192.168.1.1')

n2 = L3Device('n2', 1)
n2.add_interface(0, '192.168.1.20', 24, '192.168.1.1')

r1 = Router('r1', 4)
r1.add_interface(0, '1.0.0.0', 0, None)  # WAN
r1.add_interface(1, '192.168.1.1', 24, None)  # LAN
r1.add_nat('192.168.1.1')

o = L3Device('o', 1)
o.add_interface(0, '1.1.1.1', 0, None)

s1 = Switch('sw1', ports=4)
s2 = Switch('sw2', ports=4)
s3 = Switch('sw3', ports=4)


async def main():
	Cable(r1.ports[1], s1.ports[0])
	Cable(o.ports[0], r1.ports[0])
	Cable(n1.ports[0], s1.ports[1])
	Cable(n2.ports[0], s1.ports[2])
	#Cable(s1.ports[2], s3.ports[2])

	seq = 1
	while True:
		#n1.ping(IP('1.1.1.1'), 0, seq)
		o.ping(IP('1.0.0.0'), 0, seq)
		#r1.ping(IP('1.1.1.1'), 0, seq)
		seq += 1
		await asyncio.sleep(1.0)


if __name__ == '__main__':
	loop = asyncio.get_event_loop()
	loop.run_until_complete(main())
	loop.run_forever()
