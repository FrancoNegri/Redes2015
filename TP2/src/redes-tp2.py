import pdb
import time
import numpy
import sys
import scipy.stats
import math
from scipy.stats import t

from scapy.all import *


class Hop(object):

	def __init__(self, ip, rtt):
		self.ip = ip
		self.rtt = rtt


if __name__ == '__main__':
	alpha = 0.05
	deltas = []
	
	#hostDst = sys.argv[1]
	hostDst = '150.244.214.237' #Ejemplo es 'www.uam.es'
	
	#MAX_CANT_HOPS = sys.argv[2] #traceroute usa 30
	MAX_CANT_HOPS = 30

	hops = []
	for i in range(1,MAX_CANT_HOPS+1):
		hops.append([])
	
	#while True:
	for j in range(3):

		for hop_number in range(1,MAX_CANT_HOPS+1):
			pkt = IP(dst=hostDst, ttl=hop_number) / ICMP() 
			results, unanswered = sr(pkt, timeout=1, verbose=0)
			if len(results) > 0:
				#print 'Respondieron'
				src_ip = results[0][1].src
				rtt = results[0][1].time - results[0][0].sent_time
				hop = Hop(src_ip, rtt)
				hops[hop_number-1].append(hop) 
			#else:
				#print 'No Respondieron'
			
		#Mostrar por Pantalla los resultados
		print "HOP | IP | RTT | STD | DeltaRTT"
		distance = 1
		rttAnterior = 0
		for hops_list in hops:
			if len(hops_list) > 0:
				ips = map(lambda hop: hop.ip, hops_list)
				ip = max(ips, key=ips.count)
				rtts = map(lambda hop: hop.rtt, hops_list)
				rtt = numpy.average(rtts)
				desvio = numpy.std(rtts)
				delta_rtt = rtt - rttAnterior			
				if delta_rtt < 0:
					delta_rtt = 0
				deltas.append(delta_rtt)
				print str(distance), ' | ', ip,' | ', rtt,' | ', desvio,' | ', delta_rtt
				distance += 1
				rttAnterior = rtt
		
		normal_test_result = scipy.stats.normaltest(deltas) #(chi-square value, pvalue) 
		#print "Normal test result = {}".format(normal_test_result)
		normal = False
		if (normal_test_result[1] < alpha):
			print 'Se estima DeltaRTT con Distribucion Normal. OK'
			normal = True
		else:
			print 'No se estima DeltaRTT con Distribucion Normal. ERROR'			
				
		#Calculamos el Test Grubbs para deltaRtt (array: deltas)
		if (normal):
			deltasProm = numpy.average(deltas)
			desvio = numpy.std(deltas)
			G = (0,0)
			salto = 0			
			for d in deltas:
				zScore = abs(d-deltasProm)/desvio
				if (zScore > G[0]):
					G = (zScore,d,salto)
				salto = salto+1
			
			N = len(deltas)
			tStudent = t.ppf((1-alpha)/(2*N),N-2,0,1)
			m2 = math.sqrt((tStudent**2)/(N-2+tStudent**2))
			m1 = (N-1)/(math.sqrt(N))
			if (G[0] > m1*m2):
				print 'Se rechaza Test Grubbs (Estimamos que existen outliers)'
			else:
				print 'No se rechaza Test Grubbs (Estimamos que no existen outliers)'
		print
		
		
		




	


