# This script runs on Python 3
import socket, threading, sys, os, time, socket
sys.path.append(os.path.join(sys.path[0],'..','..','baseFunctions'))
from functions import *

class SinglePortScan(threading.Thread):
    @auto_assign
    def __init__(self,ip,port,timeout):
        threading.Thread.__init__(self)
        self.isOpen = None
    
    def run(self):

        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) idrk what this does
        self.sock.settimeout(self.timeout)

        try:
            self.sock.connect((self.ip,self.port))
            self.isOpen = True
        except socket.timeout:
            pass

def IpRangedPortScan(ip : str,portRange : list,threadPerSecond : int,timeout : float):#setting threadPerSecond to 0 won't do a thread limit NOT RECOMMENDED
    """scan ips for open ports. Port range must a list with start port and end port. Setting threadPerSecond to 0 won't do a thread limit NOT RECOMMENDED"""
    openPorts = list()
    portScanThreads = list()
    for ports in range(portRange[0],portRange[1]):
        portScanThreads.append(SinglePortScan(ip,ports,timeout))

    for threads in portScanThreads:
        threads.start()
        if threadPerSecond != 0:    #NOT RECOMMANDED
            time.sleep(1/threadPerSecond)

    for threads in portScanThreads:
        threads.join()


    for threads in portScanThreads:
        if threads.isOpen == True:
            openPorts.append(threads.port)

    return openPorts