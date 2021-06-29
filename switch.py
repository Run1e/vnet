import logging

from device import L2Device
from address import MACAddress

log = logging.getLogger(__name__)


class Switch(L2Device):
	def __init__(self, name, ports=4):
		super().__init__(name=name, ports=ports)

		self.cam = dict()

	def recv_frame(self, port, frame):
		# we never store the broadcast mac address
		if frame.source != MACAddress.broadcast() and frame.source not in self.cam:
			log.info('%s learned %s on port %s', self.name, frame.source, port)
			self.cam[frame.source] = port

		# broadcast will always flood since it's never learned
		learned_port = self.cam.get(frame.dest, None)

		if learned_port is None:
			# mac not learned, flood to every other port
			self.flood_frame(frame, except_port=port)
		else:
			# mac learned, send to specific port
			self.ports[learned_port].send_frame(frame)
