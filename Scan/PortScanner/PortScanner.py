# Port Scanner by DiamondLink
import socket, threading, sys, os, time
sys.path.append(os.path.join(sys.path[0],'..','..','baseFunctions'))
from functions import *

class SinglePortScan(threading.Thread):
    @auto_assign
    def __init__(self,ip,port,protocol,timeout):
        threading.Thread.__init__(self)
        self.isOpen = None
    
    def run(self):

        if self.protocol == "TCP":
            self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        elif self.protocol == "UDP":     #NOT WORKING RN
            self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #THIS NEED TO BE FIXED
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) idrk what this does
        self.sock.settimeout(self.timeout)

        try:
            self.sock.connect((self.ip,self.port))
            self.isOpen = True
        except socket.timeout:
            pass

        self.sock.close()

def PortScanner(ip : str,portRange : list,protocol : str,threadPerSecond : int,timeout : float):#set threadPerSecond to 0 if you don't want a thread limit
    """scan ips for open ports. Port range must a list with start port and end port. Setting threadPerSecond to 0 won't do a thread limit"""

    portScanThreads = list()

    for ports in range(portRange[0],portRange[1]):
        portScanThreads.append(SinglePortScan(ip,ports,protocol,timeout))
        portScanThreads[ports - portRange[0]].start()
        if threadPerSecond != 0:
            time.sleep(1/threadPerSecond)

    for threads in portScanThreads:
        threads.join()

    openPorts = [threads.port for threads in portScanThreads if threads.isOpen]

    return openPorts

if __name__=="__main__":
    ip = input("ip : ")
    port = input("port range : ")
    port = port.split("-")
    for i in range(len(port)):
        port[i] = int(port[i])

    threadPerSecond = int(input("Thread per second : "))
    timeout = float(input("timeout : "))
    print(PortScanner(ip,port,"TCP",threadPerSecond,timeout))
