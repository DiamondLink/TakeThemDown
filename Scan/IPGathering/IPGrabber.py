import socket, threading, sys, os, time, struct
sys.path.append(os.path.join(sys.path[0],'..','..','baseFunctions'))
from functions import *

class IpsCalculator:
    @auto_assign
    def __init__(self,startIp):

        self.startIp = struct.unpack('>I', socket.inet_aton(self.startIp))[0]
        self.incrementation = self.startIp
        self.lock = threading.Lock()

    def generateNewIp(self):
        self.lock.acquire()
        self.newIp = socket.inet_ntoa(struct.pack('>I', self.incrementation))
        self.incrementation += 1
        self.lock.release()



class SingleIPScan(threading.Thread):
    @auto_assign
    def __init__(self,port,timeout):
        threading.Thread.__init__(self)
        self.discoveredThePortOnTheIp = None

    def run(self):

        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) idrk what this does
        self.sock.settimeout(self.timeout)

        ipsCalculator.generateNewIp()
        self.ip = ipsCalculator.newIp
        try:
            self.sock.connect((self.ip,self.port))
            self.discoveredThePortOnTheIp = True
            print(self.ip)
        except socket.timeout:
            pass


def IPGrabber(ipRange : list,port : int,threadPerSecond : int,timeout : float):
    global ipsCalculator

    ipsCalculator = IpsCalculator(ipRange[0])

    ipScanThreads = list()
    ipsDiscoveredPort = list()

    startIpNumber = struct.unpack('>I', socket.inet_aton(ipRange[0]))[0]
    endIpNumber = struct.unpack('>I', socket.inet_aton(ipRange[1]))[0]

    for i in range(endIpNumber - startIpNumber):
        ipScanThreads.append(SingleIPScan(port,timeout))
    
    for threads in ipScanThreads:
        threads.start()
        if threadPerSecond != 0:
            time.sleep(1/threadPerSecond)
    
    for threads in ipScanThreads:
        threads.join()
    
    for threads in ipScanThreads:
        if threads.discoveredThePortOnTheIp:
            ipsDiscoveredPort.append(threads.ip)
    
    return ipsDiscoveredPort


if __name__ == "__main__":

    print(IPGrabber(["18.21.248.85","18.21.248.91"],80,100,1))

