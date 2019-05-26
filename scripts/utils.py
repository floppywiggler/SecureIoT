from collections import defaultdict
from datetime import datetime, timedelta
from getmac import get_mac_address
import requests
import netifaces as ni
import os


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


def scanner():
        localnet = os.system('sudo arp-scan -g --localnet -W ./scan/scan.pcap')
        pcap_to_txt = os.system('tshark -r ./scan/scan.pcap > ./scan/pcap.txt 2>/dev/null')
        locate = os.system('cat ./scan/pcap.txt | grep -i "rasp" > ./scan/raspi_list')
        extract = os.system('awk \'{print $8}\' ./scan/raspi_list > ./scan/rpi_list')
        purge_temp = os.system('rm -rf ./scan/scan.pcap && rm -rf ./scan/pcap.txt && rm -rf ./scan/raspi_list')
        os.chdir('.')

        #print('\nlocated ' + str(sum(1 for line in open('scan/rpi_list'))) + ' raspi\'s', 'yellow')
        #rpi_located = str(sum(1 for line in open('scan/rpi_list')))
        #print(rpi_located)
        #return rpi_located

scanner()

