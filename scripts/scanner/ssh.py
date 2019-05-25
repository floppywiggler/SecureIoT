import paramiko
from .scanner import ProtocolScanner
import socket


class SSHScanner(ProtocolScanner):

	def __init__(self, protocolname, portnumber, ipaddress):
		super(SSHScanner, self).__init__(protocolname, portnumber, ipaddress)

	def verifyCredentials(self, credentials):
		cur = paramiko.SSHClient()
		cur.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())  # ignore unknown hosts
		try:
			cur.connect(hostname=self.IPAddress, port=self.portNumber, username=credentials.getUsername(), password=credentials.getPassword())
		except:
			return None
		stdin, stdout, stderr = cur.exec_command('uname -a')
		evidence = stdout.readlines()[0]
		cur.close()
		return evidence
	
