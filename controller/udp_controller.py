from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import udp
from ryu.lib import hub
from ryu.lib.packet import ether_types
from operator import attrgetter
from collections import defaultdict


class UDPDetectionOFC(app_manager.RyuApp):
	dp_all = []
	dpid_block = {}
	out = {}
	OFP_VERSION = [ofproto_v1_5.OFP_VERSION]
	def __init__(self, *args, **kwargs):
		self.mac_to_port = {}
		self.datapaths = {}
		self.monitor_thread = hub.spawn(self._monitor)
		super(UDPDetectionOFC, self).__init__(*args, **kwargs)

	# initialzation of OpenFlow Controller
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def swich_feature_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# insert flow entry which has match filed ANY
		match = parser.OFPMatch()
		#match_packetin = parser.OFPMatch(eth_type=0x0800, ip_proto=17)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		#self.add_flow(datapath, 30, 0, match_packetin, actions)
		self.add_flow(datapath, 0, 0, match, actions)

	# Add Flow Entry Method
	def add_flow(self, datapath, priority, hard_timeout, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority, hard_timeout=hard_timeout, 
								match=match, instructions=inst)
		datapath.send_msg(mod)


	def send_flow_mod(self, datapath, priority, idle_timeout, match):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPFlowMod(datapath=datapath, table_id=0, priority=priority,
									idle_timeout=idle_timeout, match=match)
		datapath.send_msg(req)
	
	def _monitor(self):
		while True:
			for dp_key, dp_value in self.datapaths.items():
				if dp_key == 1:
					self.send_flow_desc_request(dp_value)
			hub.sleep(3)

	def send_flow_desc_request(self, datapath):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser

		cookie = cookie_mask = 0
		match = ofp_parser.OFPMatch(eth_type=0x0800, ip_proto=17)
		req = ofp_parser.OFPFlowDescStatsRequest(datapath, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY, cookie, cookie_mask, match)
		datapath.send_msg(req)

	# exacute method when switch receive the packet by controller
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		#get Datapath ID to identify OpenFlow switches
		dpid = datapath.id
		self.dp_all.append(datapath)
		self.mac_to_port.setdefault(dpid, {})

		#analyse the received packets using the packet library
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		dst = eth.dst
		src = eth.src
		
		#get the received port number from packet_in message
		in_port = msg.match['in_port']

		#ignore lldp packet
		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		if eth.ethertype == ether_types.ETH_TYPE_IP:
			ip = pkt.get_protocols(ipv4.ipv4)[0]
			src_ip = ip.src
			dst_ip = ip.dst
			proto_ip = ip.proto
			if proto_ip == 17: # UDP
				match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=17, ipv4_src=src_ip)
				actions = [] # Drop Action
				self.add_flow(datapath, 1, 200, match, actions)
				return

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data 

		match = parser.OFPMatch(in_port=in_port)
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
									match=match, actions=actions, data=data)
		datapath.send_msg(out)
