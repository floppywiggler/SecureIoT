from sqlalchemy import *
import random
from random import randrange, getrandbits
import time
from ipaddress import IPv4Address
from scripts.utils import getPort


def createTables():
    db = create_engine('sqlite:///iot.db')

    db.echo = True  # True means verbose log

    metadata = MetaData(db)

    cred = Table('Credentials', metadata,
                 Column('username', String, primary_key=True),
                 Column('password', String, primary_key=True)
                 )
    cred.create()

    scanResults = Table('ScanResults', metadata,
                        Column('Timestamp', String, primary_key=True),
                        Column('Vulnerable', String),
                        Column('IPAddress', String, primary_key=True),
                        Column('Device', String),
                        Column('portNumber', Integer, primary_key=True),
                        Column('protocolName', String),
                        Column('os', String),
                        Column('arch', String)
                        )

    scanResults.create()
    return None


def createAdminDB():
    db = create_engine('sqlite:///iot.db')

    db.echo = True  # True means verbose log

    metadata = MetaData(db)

    admin = Table('AdminCredentials', metadata,
                  Column('username', String),
                  Column('password', String),
                  Column('emailID', String, primary_key=True)
                  )
    admin.create()
    return None


def createUserDB():
    db = create_engine('sqlite:///iot.db')

    db.echo = True  # True means verbose log

    metadata = MetaData(db)

    users = Table('User', metadata,
                  Column('emailID', String, primary_key=True),
                  Column('Name', String),
                  Column('IPAddress', String, primary_key=True)
                  )
    users.create()
    return None


def populateScanResultsDB():
    db = create_engine('sqlite:///iot.db')

    db.echo = True  # True means verbose log

    metadata = MetaData(db)

    scanResults = Table('ScanResults', metadata, autoload=True)

    ins = scanResults.insert()

    vul = ['Yes', 'No', 'No', 'No']
    dev = ['raspberrypi', 'NodeMCU']
    protocol = ['SSH', 'FTP', 'Telnet', 'HTTP']
    os_ = ['Linux', 'RTOS']
    arch_ = ['x64', 'x86_64']

    for i in range(1000):
        vulnerable = random.choice(vul)
        device = random.choice(dev)
        mapped = zip(dev, os_)
        mapped = list(mapped)
        mapp = random.choice(mapped)
        device = mapp[0]
        _os = mapp[1]
        _arch = random.choice(arch_)
        times = randomize_time()
        ip_address = IP_generator()
        prot = random.choice(protocol)
        portN = getPort(prot)

        ins.execute(Timestamp=times, Vulnerable=vulnerable, IPAddress=ip_address, Device=device, portNumber=portN,
                    protocolName=prot, os=_os, arch=_arch)


def randomize_time():
    start_timestamp = time.mktime(time.strptime('2018-09-01 01:33:00', '%Y-%m-%d %H:%M:%S'))
    end_timestamp = time.mktime(time.strptime('2018-12-01 12:33:00', '%Y-%m-%d %H:%M:%S'))
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(randrange(start_timestamp, end_timestamp)))


def IP_generator():
    bits = 3232233985 + getrandbits(8) % 120  # generates an integer with 32 random bits
    addr = IPv4Address(bits)  # instances an IPv4Address object from those bits
    addr_str = str(addr)
    return addr_str


# createAdminDB()
populateScanResultsDB()

