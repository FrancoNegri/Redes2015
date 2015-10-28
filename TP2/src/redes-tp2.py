import pdb
import time
import numpy

from scapy.all import *


class Hop(object):

	def __init__(self, ip, rtt):
		self.ip = ip
		self.rtt = rtt


if __name__ == '__main__':
	
	MAX_CANT_HOPS = 4

	hops = []
	for i in range(1,MAX_CANT_HOPS+1):
		hops.append([])
	

	# while True:
	for j in range(3):

		for hop_number in range(1,MAX_CANT_HOPS+1):
			pkt = IP(dst='www.uam.es', ttl=hop_number) / ICMP()
			begin = time.time()
			res = sr(pkt, timeout=1, verbose=0)
			end = time.time()
			results = res[0]
			unanswered = res[1]
			if len(results[ICMP]) > 0:
				print 'Respondieron'
				src_ip = results[ICMP][0][1].src
				rtt = end - begin
				hop = Hop(src_ip, rtt)
				hops[hop_number-1].append(hop) 
			else:
				print 'No Respondieron'
			
		#Mostrar por Pantalla los resultados
		distance = 1
		rttAnterior = 0
		for hops_list in hops:
			if len(hops_list) > 0:
				print str(distance),
				ips = map(lambda hop: hop.ip, hops_list)
				ip = max(ips, key=ips.count)
				rtts = map(lambda hop: hop.rtt, hops_list)
				rtt = numpy.average(rtts)
				dEstandarRtt = rtt - rttAnterior
				print ip, rtt, dEstandarRtt 
				distance += 1
				rttAnterior = rtt




	


