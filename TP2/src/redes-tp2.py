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

def distribucionNormal(deltas):
	alphas = [0.005,0.01,0.025,0.05]	
	normal_test_result = scipy.stats.normaltest(deltas) #(chi-square value, pvalue)	
	dNormal = False
	if (normal_test_result[1] < alphas[3]):
		print 'Se estima DeltaRTT con Distribucion Normal.', 
		dNormal = True
		for alpha in alphas:
			if (normal_test_result[1] < alpha):				
				print 'Alpha = ', alpha, '. OK'	
				return dNormal, alpha		
	else:
		print 'No se estima DeltaRTT con Distribucion Normal. ERROR'
			
	return dNormal, 0	

def grubbsTest(deltas, alphaInicial):	
	rechazoTest = False
	outliers = []	
	zScores = []
	
	deltasProm = numpy.average(deltas)
	desvio = numpy.std(deltas)	
	N = len(deltas)
	tStudent = t.ppf((1-alphaInicial)/N,N-2,0,1)
	m2 = math.sqrt((tStudent**2)/(N-2+tStudent**2))
	m1 = (N-1)/(math.sqrt(N))
	
	for d in deltas:
		zScore = abs(d-deltasProm)/desvio
		zScores.append(zScore) #Por si necesitamos los zScore de cada hop			
		if (zScore > (m1*m2)):
			indice = deltas.index(d)			
			outliers.append(indice+1) #indice+1 es el salto			
			rechazoTest = True
	
	print 'zScores: ', zScores
	return rechazoTest , outliers	
	
	
if __name__ == '__main__':	
		
	hostDst = sys.argv[1]	
	MAX_CANT_HOPS = 30
	monitoreo = 0

	hops = []
	for i in range(1,MAX_CANT_HOPS+1):
		hops.append([])
		
	while True:
		monitoreo += 1
		for hop_number in range(1,MAX_CANT_HOPS+1):
			pkt = IP(dst=hostDst, ttl=hop_number) / ICMP() 
			results, unanswered = sr(pkt, timeout=1, verbose=0)
			if len(results) > 0: # Respondieron				
				src_ip = results[0][1].src
				rtt = results[0][1].time - results[0][0].sent_time
				hop = Hop(src_ip, rtt)
				hops[hop_number-1].append(hop) 			
			
		#Mostrar por Pantalla los resultados
		print 'Monitoreo Nro', monitoreo
		print "HOP | IP | RTT | STD | DeltaRTT"
		salto = 1
		rttAnterior = 0
		deltas = []
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
				print str(salto), ' | ', ip,' | ', rtt,' | ', desvio,' | ', delta_rtt
				salto += 1
				rttAnterior = rtt
						
		dNormal, alpha = distribucionNormal(deltas)
				
		#Calculamos el Test Grubbs para deltaRtt (array: deltas)
		if (dNormal):
			rechazoTest, outliers = grubbsTest(deltas, alpha)
			if (rechazoTest):
				print 'Se rechaza Test Grubbs (Estimamos que existen outliers)'
				print 'Los outliers estan en los saltos: ', outliers 				
			else:
				print 'No se rechaza Test Grubbs (Estimamos que no existen outliers)'
		print '----------------------------------------------------------------------------------'
		print
		
			
		
		
		




	


