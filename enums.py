from enum import Enum


class EtherType(Enum):
	IP = 0x0800
	ARP = 0x08CC


class ARPOperation(Enum):
	REQUEST = 1
	REPLY = 2


class Protocol(Enum):
	ICMP = 1
	TCP = 6


class ICMPType(Enum):
	ECHO_REPLY = 0
	ECHO = 8