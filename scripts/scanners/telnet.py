import telnetlib
from .scanner import ProtocolScanner
import socket


class TelnetScanner(ProtocolScanner):

    def __init__(self, protocolName, portNumber, IPAddress, macaddress):
        super(TelnetScanner, self).__init__(protocolName, portNumber, IPAddress, macaddress)

    def verifyCredentials(self, credentials):
        pswd = credentials.getPassword()
        try:
            telnet = telnetlib.Telnet(str(self.IPAddress), timeout = 2)
            telnet.read_until(b"login: ")
            telnet.write((credentials.getUsername()).encode('ascii') + b"\n")

            if pswd:
                telnet.read_until(b"Password: ")
                telnet.write(pswd.encode('ascii') + b"\n")

            telnet.write(b"exit\n")
            evidence = (telnet.read_all().decode('ascii')).split('\n')[3]
            return evidence

        except Exception as e:
            print("Exception in telnet: ", str(e))
            return None
