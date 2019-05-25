import socket

class ProtocolScanner(object):
	def __init__ (self, protocolName, portNumber, IPAddress):
		self.protocolName = protocolName
		self.portNumber = portNumber
		self.IPAddress = IPAddress

	def getProtocolName(self):
		return self.protocolName

	def getPortNumber(self):
		return self.portNumber
