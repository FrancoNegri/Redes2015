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
		
	type_to_count = {x: S.count(x) for x in set(S)}
	S_length = float(len(S))
	type_to_prob = {pkt_type: float(count)/S_length for pkt_type, count in type_to_count.iteritems()}
	type_to_info = {pkt_type: -log(prob, 2) for pkt_type, prob in type_to_prob.iteritems()}
	entropia = sum( [ type_to_info[pkt_type]*prob for pkt_type, prob in type_to_prob.iteritems() ] )

	print "-----------------------------"
	print "Probabilidad de la fuente S: {}".format(type_to_prob)
	print "Entropia de la fuente S: {}".format(entropia)
	print "-----------------------------"

	return '---Fuente S--- OK'
	
def entropyByNodes():
	global pkts
	global S1
	
	S1 = filter(lambda pkt: isARP(pkt), pkts)

	countHostsOfARPPackets(S1)

	return '---Fuente S1--- Ok' 

def countHostsOfARPPackets(arp_pkts):

	def countHostsByOp(arp_pkts, op):
		if op not in [1, 2]:
			raise Exception('op not supported')

		pkts_by_op = filter(lambda pkt: pkt.op == op, arp_pkts)
		
		src_ips = map(lambda pkt: pkt.psrc, pkts_by_op)
		src_ips_to_count = {pkt_src_ip: src_ips.count(pkt_src_ip) 
								for pkt_src_ip in set(src_ips)}
		
		dst_ips = map(lambda pkt: pkt.pdst, pkts_by_op)
		dst_ips_to_count = {pkt_dst_ip: dst_ips.count(pkt_dst_ip) 
								for pkt_dst_ip in set(dst_ips)}
		
		return src_ips_to_count, dst_ips_to_count

	print "-----------------------------"
	
	who_has_op = 1
	who_has_src_ips_to_count, who_has_dst_ips_to_count = countHostsByOp(arp_pkts, who_has_op)
	print "Who_has_src_ips_to_count: {}".format(who_has_src_ips_to_count)
	print "Who_has_dst_ips_to_count: {}".format(who_has_dst_ips_to_count)
	
	is_at_op = 2
	is_at_src_ips_to_count, is_at_dst_ips_to_count = countHostsByOp(arp_pkts, is_at_op)
	print "Is_at_src_ips_to_count: {}".format(is_at_src_ips_to_count)
	print "Is_at_dst_ips_to_count: {}".format(is_at_dst_ips_to_count)
	
	print "-----------------------------"


if __name__ == '__main__':
	print "TP1: Wiretapping"

	sniff_timeout = 1
	if len(sys.argv) > 1:
		sniff_timeout = int(sys.argv[1])
	
	print 'sniff timeout = {} segs'.format(sniff_timeout)
	sniff(prn=proccessPacket, store=0, timeout=sniff_timeout) #Cambiar el timeOut (segundos)
	
	print entropyByType()	
	print entropyByNodes()
	
