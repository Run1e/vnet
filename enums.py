from enum import Enum


class EtherType(Enum):
	IP = 0x0800
	ARP = 0x08CC


class ARPOperation(Enum):
	REQUEST = 1
	REPLY = 2
