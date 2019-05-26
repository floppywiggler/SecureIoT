from collections import defaultdict
from datetime import datetime, timedelta
from getmac import get_mac_address
import requests
import netifaces as ni

def parseEvidence(evidence):
    evidenceSplit = evidence.split()
    d = defaultdict()
    d['os'] = evidenceSplit[0]
    try:
        d['arch'] = evidenceSplit[10]
    except:
        d['arch'] = "NA"
    try:
        d['dev'] = evidenceSplit[1]
    except:
        d['dev'] = "NA"
    return d


def currentTime():
    return datetime.now().replace(microsecond=0)


def getPort(protocol):
    """ A list of ports we will check for """
    p = defaultdict()
    p["SSH"] = 22
    p["FTP"] = 21
    p["HTTP"] = 80
    p["Telnet"] = 23
    p["RDP"] = 3389

    return p[protocol]

def getMAC(ip):
    ip_mac = get_mac_address(ip="{}".format(ip))
    return ip_mac

def resolveVendor(MAC):
    MAC_URL = 'http://macvendors.co/api/%s'
    r = requests.get(MAC_URL % '{}'.format(MAC))
    obj = r.json()
    vendor = (obj['result']['company'])
    return vendor

def getLast15Dates():
    dates = []
    for i in range(15):
        d = datetime.today() - timedelta(days=14 - i)
        dates.append(d.strftime('%Y-%m-%d'))
    return dates



def get_ip_address():
    """ Returns IP address of interface eth0 on RPi"""
    ni.ifaddresses('eth0')
    ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
    return ip


class Subnet_util:
    def __init__(self, ip_address, subnet_mask):
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask

    def check_ip(self):
        # check IPv4 ip address for validity
        # will return True if valid, False if not valid

        a = self.ip_address.split('.')
        if (len(a) == 4) \
           and '' not in a \
           and (1 <= int(a[0]) <= 223) and (int(a[0]) != 127) \
           and (0 <= int(a[1]) <= 255 and 0 <= int(a[2]) <= 255 and 0 <= int(a[3]) <= 255) \
           and (int(a[0]) != 169 or int(a[1]) != 254):
            return True
        else:
            return False

    def check_mask(self):
        # check IPv4 subnet mask for validity
        # will return True if valid, False if not valid

        valid_masks = [255, 254, 252, 248, 240, 224, 192, 128, 0]
        b = self.subnet_mask.split('.')
        if (len(b) == 4) \
           and '' not in b \
           and (0 < int(b[0]) <= 255) and (int(b[0]) in valid_masks) \
           and (int(b[1]) in valid_masks) \
           and (int(b[2]) in valid_masks) \
           and (int(b[3]) in valid_masks) \
           and (int(b[0]) >= int(b[1]) >= int(b[2]) >= int(b[3])) \
           and (not((int(b[0]) != 255) and (int(b[1]) > 0))) \
           and (not((int(b[1]) != 255) and (int(b[2]) > 0))) \
           and (not((int(b[2]) != 255) and (int(b[3]) > 0))):
            return True
        else:
            return False

    def ip(self, binary=False):
        # return ip address in decimal or binary format

        while self.check_ip() is True:
            if binary is False:
                return self.ip_address
            else:
                ip_octets_padded = []
                ip_octets_decimal = self.ip_address.split('.')
                for octet_index in range(0, 4):
                    binary_octet = bin(int(ip_octets_decimal[octet_index])).split('b')[1]
                    if len(binary_octet) < 8:
                        binary_octet_padded = binary_octet.zfill(8)
                        ip_octets_padded.append(binary_octet_padded)
                    else:
                        ip_octets_padded.append(binary_octet)
                binary_ip = ''.join(ip_octets_padded)
                return binary_ip
        return IndexError

    def subnet(self, binary=False, wildcard=False):
        # return subnet mask or wildcard mask in decimal or binary format

        while self.check_mask() is True:
            if binary is False and wildcard is False:
                return self.subnet_mask
            elif binary is True and wildcard is False:
                mask_octets_decimal = self.subnet_mask.split('.')
                mask_octets_binary = []
                for octet_index in range(0, len(mask_octets_decimal)):
                    binary_octet = bin(int(mask_octets_decimal[octet_index])).split("b")[1]
                    if len(binary_octet) == 8:
                            mask_octets_binary.append(binary_octet)
                    elif len(binary_octet) < 8:
                            padded_octet = binary_octet.zfill(8)
                            mask_octets_binary.append(padded_octet)
                mask_binary = ''.join(mask_octets_binary)
                return mask_binary
            elif wildcard is True:
                mask_octets_decimal = self.subnet_mask.split(".")
                wildcard_octets = []
                for w_octet in mask_octets_decimal:
                    wild_octet = 255 - int(w_octet)
                    wildcard_octets.append(str(wild_octet))
                wildcard_mask = '.'.join(wildcard_octets)
                if binary is False:
                    return wildcard_mask
                else:
                    wildcard_octets_binary = []
                    for octet_index in range(0, len(mask_octets_decimal)):
                        binary_octet = bin(int(mask_octets_decimal[octet_index])).split("b")[1]
                        if len(binary_octet) == 8:
                                wildcard_octets_binary.insert(0, binary_octet)
                        elif len(binary_octet) < 8:
                                padded_octet = binary_octet.zfill(8)
                                wildcard_octets_binary.insert(0, padded_octet)
                    wildcard_mask_binary = ''.join(wildcard_octets_binary)
                    return wildcard_mask_binary
        return IndexError

    def network(self, binary=False):
        # return network address in decimal or binary format

        while self.check_ip() is True and self.check_mask() is True:
            no_of_zeros = self.subnet(binary=True).count('0')
            no_of_ones = 32 - no_of_zeros
            if binary is True:
                network_address_binary = self.ip(binary=True)[:no_of_ones] + ('0' * no_of_zeros)
                return network_address_binary
            else:
                network_address_binary = self.ip(binary=True)[:no_of_ones] + ('0' * no_of_zeros)
                net_ip_octets = []
                for octet in range(0, len(network_address_binary), 8):
                    net_ip_octet = network_address_binary[octet:octet + 8]
                    net_ip_octets.append(net_ip_octet)
                net_ip_address = []
                for octet in net_ip_octets:
                    net_ip_address.append(str(int(octet, 2)))
                network_address = '.'.join(net_ip_address)
                return network_address
        return IndexError

    def broadcast(self, binary=False):
        # return broadcast address in decimal or binary format

        while self.check_ip() is True and self.check_mask() is True:
            no_of_zeros = self.subnet(binary=True).count('0')
            no_of_ones = 32 - no_of_zeros
            if binary is True:
                broadcast_address_binary = self.ip(binary=True)[:no_of_ones] + ('1' * no_of_zeros)
                return broadcast_address_binary
            else:
                broadcast_address_binary = self.ip(binary=True)[:no_of_ones] + ('1' * no_of_zeros)
                bcast_octets = []
                for octet in range(0, len(broadcast_address_binary), 8):
                    bcast_octet = broadcast_address_binary[octet:octet + 8]
                    bcast_octets.append(bcast_octet)
                bcast_address = []
                for octet in bcast_octets:
                    bcast_address.append(str(int(octet, 2)))
                broadcast_address = '.'.join(bcast_address)
                return broadcast_address
        return IndexError

    def subnet_bits(self):
        # Return /x representation of a valid subnet mask.  Will return
        # IndexError if valid subnet mask not provided.
        # '255.255.255.0' returns '/24'
        # '255.128.128.0' returns IndexError

        while self.check_mask() is True:
            binary = self.subnet(binary=True)
            no_of_ones = str(binary.count('1'))
            return ('/') + no_of_ones
        return IndexError

    def host_count(self):
        # Return the number of valid hosts that exist in the subnet.  Will
        # return IndexError if valid subnet mask not provided.

        while self.check_mask() is True:
            no_of_zeros = self.subnet(binary=True).count('0')
            no_of_ones = 32 - no_of_zeros
            no_of_hosts = abs(2 ** no_of_zeros - 2)
            return no_of_hosts
        return IndexError
