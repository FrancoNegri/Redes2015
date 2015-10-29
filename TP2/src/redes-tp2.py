import pdb
import time
import numpy
import sys

from scapy.all import *


class Hop(object):

	def __init__(self, ip, rtt):
		self.ip = ip
		self.rtt = rtt


if __name__ == '__main__':
	
	#hostDst = sys.argv[1]
	hostDst = '150.244.214.237'
	
	#MAX_CANT_HOPS = sys.argv[2] #traceroute usa 30
	MAX_CANT_HOPS = 10

	hops = []
	for i in range(1,MAX_CANT_HOPS+1):
		hops.append([])
	

	#while True:
	for j in range(3):

		for hop_number in range(1,MAX_CANT_HOPS+1):
			pkt = IP(dst=hostDst, ttl=hop_number) / ICMP() #Ejemplo es 'www.uam.es'
			results, unanswered = sr(pkt, timeout=1, verbose=0)
			if len(results[ICMP]) > 0:
				#print 'Respondieron'
				src_ip = results[ICMP][0][1].src
				rtt = results[ICMP][0][1].time - results[ICMP][0][0].sent_time
				hop = Hop(src_ip, rtt)
				hops[hop_number-1].append(hop) 
			#else:
				#print 'No Respondieron'
			
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
				dEstandardRtt = rtt - rttAnterior
				print ip, rtt, dEstandardRtt 
				distance += 1
				rttAnterior = rtt
		print




	


