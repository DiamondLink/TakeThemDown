import socket, sys, os, time, struct, threading
from multiprocessing import Process,Manager
from multiprocessing.managers import BaseManager
from pysnmp.entity.rfc3413.oneliner import cmdgen
#from scapy.all import *
#import subprocess
#import pandas

sys.path.append(os.path.join(sys.path[0],'..','..','baseFunctions'))
from functions import *

class IpsCalculator(threading.Thread):
    @auto_assign
    def __init__(self,startIp,endIp):
        threading.Thread.__init__(self)

        self.incrementation = self.startIp
        self.lock = threading.Lock()
        self.ips = dict()

    def generateAndGetNewIp(self):
        self.lock.acquire()
        self.newIp = socket.inet_ntoa(struct.pack('>I', self.incrementation))
        self.incrementation += 1
        return self.newIp
        self.lock.release()


class SingleIPScan(Process):
    @auto_assign
    def __init__(self,port,protocol,timeout,id,IpClass):
        super(SingleIPScan, self).__init__()

        self.discoveredThePortOnTheIp = None

    def run(self):
        self.ip = self.IpClass.generateAndGetNewIp()

        if self.protocol == "TCP":
            self.discoveredThePortOnTheIp = tcpScan(self.ip,self.port,self.timeout)

        elif self.protocol == "UDP":
            self.discoveredThePortOnTheIp = udpScan(self.ip,self.port,self.timeout,2)

def tcpScan(ip,port,timeout):
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) idrk what this does
        sock.settimeout(timeout)
        sock.connect((ip,port))
        return True
    except socket.timeout:
        return False

def udpScan(ip,port,timeout,retries):
    cmdGen = cmdgen.CommandGenerator()
    community_string = "public"
    authentication_token = cmdgen.CommunityData(community_string, mpModel = 0)

    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
		authentication_token,
		cmdgen.UdpTransportTarget((ip, port), timeout = timeout, retries = retries),
		cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0)
	)

    if errorIndication:
        return False
    elif errorStatus:
        return False
    else:
        return True

def IPGrabber(ipRange : list,port : int,protocol : str,threadPerSecond : int,timeout : float):

    ipsDiscoveredPort = list()

    ipScanThreads = list()

    startIpNumber = struct.unpack('>I', socket.inet_aton(ipRange[0]))[0]
    endIpNumber = struct.unpack('>I', socket.inet_aton(ipRange[1]))[0]

    BaseManager.register("IpsCalculator", IpsCalculator)
    manager = BaseManager()
    manager.start()
    ipsCalculator = manager.IpsCalculator(startIpNumber,endIpNumber)

    ipScanThreads = [SingleIPScan(port,protocol,timeout,i,ipsCalculator) for i in range(endIpNumber - startIpNumber)]
    
    for processes in ipScanThreads : processes.start()

    for processes in ipScanThreads : processes.join()

    ipsDiscoveredPort = [processes.ip for processes in ipScanThreads if processes.discoveredThePortOnTheIp]
    
    return ipsDiscoveredPort

if __name__ == "__main__":
    a = 0
    startTime = time.time()
    if a == 1:
        startTime = time.time()
        ipRange = input("ip range : ")
        port = int(input("port : "))
        protocol = input("protocol (TCP/UDP): ")
        threadPerSecond = int(input("threads per second (0 for no limit) : "))
        timeout = float(input("timeout : "))
    print(IPGrabber(["12.86.249.200","12.86.249.255"],161,"UDP",0,1))
    print("Done ! Scanned in {} s".format(time.time() - startTime))

