import logging

from device import Device

log = logging.getLogger(__name__)


class Switch(Device):
	def __init__(self, name, ports=4):
		super().__init__(name=name, ports=ports)

		self.cam = dict()

	def recv(self, port, frame):
		log.info('%s recv on port %s', self.name, port)

		if frame.source not in self.cam:
			log.info('%s learned mac %s on port %s', self.name, frame.source, port)
			self.cam[frame.source] = port

		learned_port = self.cam.get(frame.dest, None)

		if learned_port is None:
			# mac not learned, flood to every other port

			for idx, other_port in enumerate(self.ports):
				# don't send back to same port
				if idx == port:
					continue

				log.info('%s flooding on port %s', self.name, idx)
				other_port.send(frame)

		else:
			# mac learned, send to specific port
			log.info('%s sending frame to learned port %s', self.name, learned_port)
			self.ports[learned_port].send(frame)
