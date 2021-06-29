from asyncio import create_task, sleep
from random import random, randint


class Port:
	def __init__(self, callback):
		self.callback = callback

		self.cable = None

	@property
	def connected(self):
		return bool(self.cable)

	def plug(self, cable):
		self.cable = cable

	def send_frame(self, frame):
		if not self.cable:
			return

		create_task(self.cable.send(self, frame))

	def recv_frame(self, frame):
		self.callback(frame)


class Cable:
	def __init__(self, a, b, delay_min=50, delay_max=200, drop_chance=0.0):
		self.a = a
		self.b = b

		self.delay_min = delay_min
		self.delay_max = delay_max
		self.drop_chance = drop_chance

		self.a.plug(self)
		self.b.plug(self)

	async def send(self, from_port, frame):
		other = self.b if from_port is self.a else self.a

		if random() < self.drop_chance:
			return

		delay = randint(self.delay_min, self.delay_max) / 1000
		await sleep(delay)

		other.recv_frame(frame)
