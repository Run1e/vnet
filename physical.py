from asyncio import create_task, sleep
from random import random


class Port:
	def __init__(self, callback):
		self.callback = callback
		self.cable = None

	def plug(self, cable):
		self.cable = cable

	def send_frame(self, frame):
		if not self.cable:
			return

		create_task(self.cable.send(self, frame))

	def recv_frame(self, frame):
		self.callback(frame)


class Cable:
	def __init__(self, a, b):
		self.a = a
		self.b = b

		self.a.plug(self)
		self.b.plug(self)

	async def send(self, from_port, frame):
		other = self.b if from_port is self.a else self.a
		await sleep(random() / 2)
		other.recv_frame(frame)
