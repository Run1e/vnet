class Frame:
	def __init__(self, dest, source, ethertype, payload):
		self.dest = dest
		self.source = source
		self.ethertype = ethertype
		self.payload = payload

	def __repr__(self):
		return f'<Frame dest={self.dest} source={self.source}>'


class Packet:
	# also called an IP datagram in some cases
	def __init__(self, dest, source, data, ttl=8):
		self.dest = dest
		self.source = source
		self.data = data
		self.ttl = ttl


class TCPSegment:
	def __init__(self, source_port, dest_port, seq_number, ack_number, data):
		self.source_port = source_port
		self.dest_port = dest_port
		self.seq_number = seq_number
		self.ack_number = ack_number
		self.data = data
