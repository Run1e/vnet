class Port:
	def __init__(self, callback):
		self.callback = callback
		self.cable = None

	def plug(self, cable):
		self.cable = cable

	def send(self, frame):
		if self.cable:
			self.cable.send(self, frame)

	def recv(self, frame):
		self.callback(frame)


class Cable:
	def __init__(self, a, b):
		self.a = a
		self.b = b

		self.a.plug(self)
		self.b.plug(self)

	def send(self, from_port, frame):
		other = self.b if from_port is self.a else self.a
		other.recv(frame)
