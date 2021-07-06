import asyncio
import logging
from random import randint

import coloredlogs

from device import L3Device
from logical import *
from physical import Cable
from router import Router
from switch import Switch

from pprint import pprint as p

coloredlogs.install(
	level='DEBUG',
	fmt='[%(name)s] %(message)s',
	level_styles=dict(warn=dict(color='green'), info=dict(color='blue'), debug=dict(color='white'))
)

log = logging.getLogger()

node1 = L3Device('node1', 1)
node1.add_interface(0, '10.0.1.10', 24, '10.0.1.1')

#node2 = L3Device('node2', 1)
#node2.add_interface(0, '10.0.2.20', 24, '10.0.2.1')

node2 = L3Device('node2', 1)
node2.add_interface(0, '8.8.8.8', 0, None)

router1 = Router('router1', 4)
router1.add_interface(0, '1.1.1.1', 32, None, wan=True)
router1.add_interface(1, '10.0.1.1', 24, None, nat=True)
router1.add_interface(1, '10.0.2.1', 24, None, nat=True)
router1.add_route(Route(IP('0.0.0.0'), IP.from_cidr(0), IP('1.1.1.2'), IP('1.1.1.1')))

router2 = Router('router2', 4)
router2.add_interface(0, '1.1.1.2', 32, None)
router2.add_interface(1, '1.1.1.3', 32, None)
router2.add_route(Route(IP('0.0.0.0'), IP.from_cidr(0), IP('1.1.1.1'), IP('1.1.1.2')))
router2.add_route(Route(IP('8.0.0.0'), IP.from_cidr(8), None, IP('1.1.1.3')))

switch1 = Switch('switch1', ports=4)
switch2 = Switch('switch2', ports=4)


async def main():
	from pprint import pprint as p

	Cable(router1.ports[0], router2.ports[0])

	Cable(router1.ports[1], switch1.ports[0])
	Cable(router2.ports[1], switch2.ports[0])

	Cable(node1.ports[0], switch1.ports[1])
	Cable(node2.ports[0], switch2.ports[1])

	p1 = randint(0, 100)
	p2 = randint(100, 200)

	seq = 1
	while True:
		node1.ping(IP('8.8.8.8'), p1, seq)
		# node1.ping(IP('1.1.1.1'), p1, seq)
		# node3.ping(IP('1.1.1.1'), p2, seq)
		# router1.ping(IP('1.1.1.1'), p2, seq)
		seq += 1
		await asyncio.sleep(1.0)


if __name__ == '__main__':
	loop = asyncio.get_event_loop()
	loop.run_until_complete(main())
	loop.run_forever()
