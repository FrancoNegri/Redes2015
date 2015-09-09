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
		
		if isARP(pkt):
			printARPdata(pkt)
	
	else:
		print 'Packet has no attribute type' # Comentar en el informe que ignoramos los paquetes sin tipo

def isARP(pkt):
	return hasattr(pkt, 'type') and pkt.type == 2054 #2054 es ARP, 2048 es IP

def printARPdata(pkt):
	ip_src, mac_src = pkt.psrc, pkt.src
	ip_dst, mac_dst = pkt.pdst, pkt.dst
	if pkt.op == 1:
		print 'Who has? ip {}, tell ip {}, at mac {}'.format(ip_dst, ip_src, mac_src)
	elif pkt.op == 2:
		print 'The ip {} is at mac {}, telling ip {}, at mac {}'.format(ip_src, mac_src, ip_dst, mac_dst)

def entropyByType():
	global S
		
	type_to_count = {x: S.count(x) for x in S}
	S_length = float(len(S))
	type_to_prob = {type: float(count)/S_length for type, count in type_to_count.iteritems()}
	type_to_info = {type: -log(prob, 2) for type, prob in type_to_prob.iteritems()}
	entropia = sum( [ type_to_info[type]*prob for type, prob in type_to_prob.iteritems() ] )

	print "Probabilidad de la fuente S: {} \n -----------------------------".format(type_to_prob)
	print "Entropia de la fuente S: {} \n -----------------------------".format(entropia)

	return '---Fuente S--- OK'
	
def entropyByNodes():
	global pkts
	global S1
	
	S1 = filter(lambda pkt: isARP(pkt), pkts)

	return '---Fuente S1--- Ok' 
	

if __name__ == '__main__':
	print "TP1: Wiretapping"

	sniff(prn=proccessPacket, store=0, timeout=10) #Cambiar el timeOut (segundos)
	
	print entropyByType()	
	print entropyByNodes()
	
