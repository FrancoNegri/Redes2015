import sys
from scapy.all import *
from math import log

S = [] #fuente S
S1 = [] #fuente S1
pkts = []

def proccessPacket(pkt):
	global S
	global pkts
	pkts.append(pkt)
	if hasattr(pkt, 'type'):
		S.append(pkt.type)
	else:
		print 'Packet has no attribute type' # Es normal que haya paquetes sin tipo ??

def entropyByType():
	global S
	
	sniff(prn=proccessPacket, store=0, timeout=5) #Cambiar el timeOut (segundos)
	
	type_to_count = {x: S.count(x) for x in S}
	#print type_to_count
	
	type_to_prob = {}
	for type, count in type_to_count.iteritems():
		type_to_prob[type] = float(count)/float(len(S))
	print "Probabilidad de la fuente S:"
	print type_to_prob
	print '-----------------------------'
	
	type_to_info = {}
	for type, prob in type_to_prob.iteritems():
		type_to_info[type] = -log(prob, 2)
	#print type_to_info
	
	entropia = 0
	for type, prob in type_to_prob.iteritems():
		info = type_to_info[type]
		info_prob_prod = prob*info
		entropia += info_prob_prod
	print "Entropia de la fuente S: "
	print entropia
	print '-----------------------------'
	
	return '---Fuente S--- OK'
	

def entropyByNodes():
	global pkts
	global S1
	
	for pkt in pkts:
		if pkt.type == 2054: #2054 es ARP, 2048 es IP
			S1.append(pkt)
	
	for pkt in S1:
		if pkt.op in (1,2): #who-has o is-at
			ip_src = pkt.psrc
			ip_dst = pkt.pdst
			if pkt.op == 1:
				op = 'who-has'
			else:
				op = 'is-at'
				
			print(ip_src, ip_dst, op)
			
	return '---Fuente S1--- Ok' 
		
if __name__ == '__main__':
	print "TP1: Wiretapping"
	print entropyByType()	
	print entropyByNodes()
	
