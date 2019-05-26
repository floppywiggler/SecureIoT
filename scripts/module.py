from .utils import *

from werkzeug.security import generate_password_hash, check_password_hash
import ipaddress
import multiprocessing as mp


from sqlalchemy import *
from .scanners.scanner import ProtocolScanner
from .scanners.ssh import SSHScanner
from .scanners.ftp import FTPScanner
from .scanners.telnet import TelnetScanner
import socket
from datetime import datetime

DEBUG = False


class Person:

    def __init__(self, name, emailID):
        self.name = name
        self.emailID = emailID

    def getName(self):
        return self.name

    def getEmail(self):
        return self.emailID


class Admin(Person):

    def __init__(self, name, emailID, credential):
        Person.__init__(self, name, emailID)
        self.credential = credential
        self.db = DatabaseHandler()

    def verifyCredentials(self, cred):
        return self.db.verifyAdminCredentials(cred)

    def getCredential(self):
        return self.credential


class Credentials():
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def getUsername(self):
        return self.username

    def getPassword(self):
        return self.password


class ScanResults():
    def __init__(self, timestamp, vulnerable, IPAddress, deviceName, portNumber, protocolName, os, architecture):
        self.timestamp = timestamp
        self.vulnerable = vulnerable
        self.IPAddress = IPAddress
        self.deviceName = deviceName
        self.portNumber = portNumber
        self.protocolName = protocolName
        self.os = os
        self.architecture = architecture


class DeviceScanner():
    def __init__(self):
        self.admin = Admin("admin name", "admin email", Credentials("admin", "password"))
        manager = mp.Manager()
        self.scanResults = manager.list()
        self.db = DatabaseHandler()

    def scanRange(self, startIP, endIP):
        try:
            start_IP = ipaddress.IPv4Address(startIP)
            end_IP = ipaddress.IPv4Address(endIP)
        except:
            return "invalidIP"

        start_IP = ipaddress.IPv4Address(startIP)
        end_IP = ipaddress.IPv4Address(endIP)
        if start_IP > end_IP:
            return "invalidIP"

        processes = [mp.Process(target=self.attemptLogin, args=(IPAddress,)) for IPAddress in
                     range(int(start_IP), int(end_IP + 1))]

        for p in processes:
            # print("Starting process")
            p.start()

        for p in processes:
            p.join()
            print("Joining process")


        return self.scanResults

    def attemptLogin(self, IPAddress):
        IPAddress = str(ipaddress.IPv4Address(IPAddress))
        try:
            socket.gethostbyaddr(IPAddress)
        except socket.herror:
            print("Unknown host {0}".format(IPAddress))
            return
        protocols = ["SSH", "FTP", "Telnet"]
        for protocol in protocols:
            # print(IPAddress, protocol)
            if ProtocolScanner(protocol, getPort(protocol), IPAddress).isPortOpen() != 0:
                currentResult = {
                    "vulnerable": "Port Closed",
                    "timestamp": str(currentTime()),
                    "ip": IPAddress,
                    "port": getPort(protocol),
                    "protocol": protocol,
                    "os": "NA",
                    "arch": "NA",
                    "device": "NA",
                }
                self.scanResults.append(currentResult)
                print(currentResult)
                continue
            protocolScanner = globals()[protocol + "Scanner"](protocol, getPort(protocol), IPAddress)
            credentials = self.db.getCredentialsFromDB()
            # checking all username and passwords in DB
            detected = False
            for cred in credentials:
                if detected:
                    break
                scanResult = protocolScanner.verifyCredentials(cred)
                curTime = currentTime()
                try:
                    parsedEvidence = parseEvidence(scanResult)
                    currentResult = {
                        "vulnerable": "Yes",
                        "timestamp": str(curTime),
                        "ip": IPAddress,
                        "port": getPort(protocol),
                        "protocol": protocol,
                        "os": parsedEvidence["os"],
                        "arch": parsedEvidence["arch"],
                        "device": parsedEvidence["dev"]
                    }
                    detected = True
                    self.db.insertIntoScanResults(curTime, "Yes", IPAddress, parsedEvidence["dev"], getPort(protocol),
                                                  protocol, parsedEvidence["os"], parsedEvidence["arch"])
                    self.scanResults.append(currentResult)
                    print(currentResult)
                except:
                    continue
            if detected is False:
                currentResult = {
                    "vulnerable": "No",
                    "timestamp": str(currentTime()),
                    "ip": IPAddress,
                    "port": getPort(protocol),
                    "protocol": protocol,
                    "os": "NA",
                    "arch": "NA",
                    "device": "NA"
                }
                self.db.insertIntoScanResults(curTime, "No", IPAddress, "NA", getPort(protocol), protocol, None, None)
                print(currentResult)
                self.scanResults.append(currentResult)

    def displayScanResuts(self):
        # Display scan results
        print(self.scanResults)
        return None


class DatabaseHandler():
    def __init__(self):
        self.db = create_engine('sqlite:///iot.db')
        self.db.echo = False

    def getCredentialsFromDB(self):
        metadata = MetaData(self.db)
        credentials = Table('Credentials', metadata, autoload=True)
        s = credentials.select()
        rs = s.execute()
        rows = rs.fetchall()
        credentials = []
        for row in rows:
            cred = Credentials(row.username, row.password)
            credentials.append(cred)
        return credentials

    def getAdminCredentialsFromDB(self):
        metadata = MetaData(self.db)
        credentials = Table('AdminCredentials', metadata, autoload=True)
        s = credentials.select()
        rs = s.execute()
        rows = rs.fetchall()
        admin_credentials = []
        username = {}
        password = {}
        for row in rows:
            admin_cred = Admin(row.username, row.emailID, Credentials(row.username, row.password))
            admin_credentials.append(admin_cred)
        return admin_credentials

    def getScanResultsForDate(self, date):
        metadata = MetaData(self.db)
        scan_results = Table('ScanResults', metadata, autoload=True)
        entities = scan_results.select()
        rows = entities.execute().fetchall()
        scanResults = []
        for row in rows:
            if row.Timestamp.count(date) > 0:
                scanResult = ScanResults(row.Timestamp, row.Vulnerable, row.IPAddress, row.Device, row.portNumber,
                                         row.protocolName, row.os, row.arch)
                scanResults.append(scanResult)

        return scanResults

    def getScanResultsVulnerableCountForDate(self, date):
        metadata = MetaData(self.db)
        scan_results = Table('ScanResults', metadata, autoload=True)
        entities = scan_results.select()
        rows = entities.execute().fetchall()
        count = 0
        for row in rows:
            if row.Timestamp.count(date) > 0 and row.Vulnerable == "Yes":
                count += 1

        return count

    def getScanResultsFromDB(self):
        metadata = MetaData(self.db)
        scanRes = Table('ScanResults', metadata, autoload=True)
        s = scanRes.select()
        rs = s.execute()
        rows = reversed(rs.fetchall())  # whats the query?
        scanResults = []
        for row in rows:
            scanResult = ScanResults(row.Timestamp, row.Vulnerable, row.IPAddress, row.Device, row.portNumber,
                                     row.protocolName, row.os, row.arch)
            scanResults.append(scanResult)
        scanResults.sort(key=lambda x: x.timestamp, reverse=True)
        return scanResults

    def insertIntoDefaultCredentials(self, username, password):
        metadata = MetaData(self.db)
        credentials = Table('Credentials', metadata, autoload=True)
        insert_cred = credentials.insert()
        insert_cred.execute(username=username, password=password)
        return None

    def deleteFromDefaultCredentials(self, username, password):
        metadata = MetaData(self.db)
        credentials = Table('Credentials', metadata, autoload=True)
        delete_cred = credentials.delete().where(
            and_(credentials.c.username == username, credentials.c.password == password))
        delete_cred.execute()
        return None

    def insertIntoScanResults(self, time, vulnerable, IPAddress, device, portNumber, protocolName, os, arch):
        metadata = MetaData(self.db)
        scan_results = Table('ScanResults', metadata, autoload=True)
        insert_scan_results = scan_results.insert()
        insert_scan_results.execute(Timestamp=time, Vulnerable=vulnerable, IPAddress=IPAddress, Device=device,
                                    portNumber=portNumber, protocolName=protocolName, os=os, arch=arch)
        return None

    def purgeScanResults(self, date):
        metadata = MetaData(self.db)
        scan_results = Table('ScanResults', metadata, autoload=True)
        select_results = scan_results.select().execute().fetchall()
        for row in select_results:
            try:
                time_before = datetime.strptime(row.Timestamp, '%Y-%m-%d %H:%M:%S')

                time_compare = datetime.strptime(date + ' 23:59:59', '%Y-%m-%d %H:%M:%S')
                if time_before < time_compare:
                    delete_scan_results = scan_results.delete(scan_results.c.Timestamp == row.Timestamp)
                    delete_scan_results.execute()
            except Exception as exception:
                print(exception)
                continue
        return None

    def insertNewAdmin(self, admin):
        metadata = MetaData(self.db)
        admin_cred = Table('AdminCredentials', metadata, autoload=True)
        insert_admin = admin_cred.insert()
        cred = admin.getCredential()
        insert_admin.execute(username=cred.getUsername(), password=cred.getPassword(), emailID=admin.emailID)
        return "Admin Added"

    def deleteAdmin(self, usernameOrEmailID):
        metadata = MetaData(self.db)
        admin_cred = Table('AdminCredentials', metadata, autoload=True)
        print("here")
        delete_admin = admin_cred.delete().where(
            or_(admin_cred.c.username == usernameOrEmailID, admin_cred.c.emailID == usernameOrEmailID))
        delete_admin.execute()
        return None

    def verifyAdminCredentials(self, cred):
        metadata = MetaData(self.db)
        credentials = Table('AdminCredentials', metadata, autoload=True)
        rows = credentials.select().execute().fetchall()
        for row in rows:
            if row.username == cred.getUsername() and row.password == cred.getPassword():
                return True
        return False

    def getEmailIdFromIp(self, IPAddress):
        metadata = MetaData(self.db)
        users = Table('User', metadata, autoload=True)
        entities = users.select()
        rows = entities.execute().fetchall()
        for row in rows:
            return row.emailID

# db = DatabaseHandler()
# db.purgeScanResults("2018-11-02")
# print(db.getAdminCredentialsFromDB()[1].getCredential().getUsername())
