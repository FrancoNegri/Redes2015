import sys
from scapy.all import *
from math import log

S = [] #fuente S
S1 = [] #fuente S1
pkts = []

def proccessPacket(pkt):
	global S
	global pkts	
	if hasattr(pkt, 'type'):
		S.append(pkt.type)
		pkts.append(pkt)
	else:
		print 'Packet has no attribute type' # Comentar en el informe que ignoramos los paquetes sin tipo

def entropyByType():
	global S
		
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
			mac_src = pkt.src
			ip_dst = pkt.pdst
			mac_dst = pkt.dst			
			if pkt.op == 1:
				op = 'who-has'
				print 'Who has? ip {}, tell ip {}, at mac {}'.format(ip_dst, ip_src, mac_src)
			else:
				op = 'is-at'				
				print 'The ip {} is at mac {}, telling ip {}, at mac {}'.format(ip_src, mac_src, ip_dst, mac_dst)

			print(ip_src, mac_src, ip_dst, mac_dst, op)
			
	return '---Fuente S1--- Ok' 
		
if __name__ == '__main__':
	print "TP1: Wiretapping"

	sniff(prn=proccessPacket, store=0, timeout=5) #Cambiar el timeOut (segundos)
	print entropyByType()	
	print entropyByNodes()
	
