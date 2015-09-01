from scapy.all import *
from math import log


S = []
S1 = []


def entropyByType():

	def proccessPacket(pkt):
		global S
		if hasattr(pkt, 'type'):
			S.append(pkt.type)
		else:
			print 'Packet has no attribute type' # Es normal que haya paquetes sin tipo ??

	sniff(prn=proccessPacket, store=0)
	
	type_to_count = {x: S.count(x) for x in S}
	print type_to_count
	
	type_to_prob = {}
	for type, count in type_to_count.iteritems():
		type_to_prob[type] = float(count)/float(len(S))
	print type_to_prob
	
	type_to_info = {}
	for type, prob in type_to_prob.iteritems():
		type_to_info[type] = -log(prob, 2)
	print type_to_info
	
	entropia = 0
	for type, prob in type_to_prob.iteritems():
		info = type_to_info[type]
		info_prob_prod = prob*info
		entropia += info_prob_prod
	return entropia

def entropyByNodes():

	def proccessPacket(pkt):
		global S1
		print pkt.dst, pkt.src

	sniff(prn=proccessPacket, filter="arp", store=0)




if __name__ == '__main__':
	# print entropyByType()	
	print entropyByNodes()