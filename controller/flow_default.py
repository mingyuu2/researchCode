#フローエントリの飽和対策のプログラムです(動作確認用)。
#作成開始日 2023/07/10

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp
from operator import attrgetter
from ryu.lib import hub

class test(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]
    save_comb={}
    #out = {}
    #dp_all = []
    dpid_block = {}
    syn_count={} #SYNパケットの数
    dest_count={} #宛先IPアドレスの数
    
    def __init__(self, *args, **kwargs):
        super(test, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.detection_thread = hub.spawn(self._detection)


        
       
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    #Packet_In用のフローエントリ挿入
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match_packetin = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=(2, 18))
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 30, 0, match_packetin, actions)
        self.add_flow(datapath, 0, 0, match, actions)
        
        
    #通常のフローエントリを挿入
    def add_flow(self, datapath, priority, hard_timeout, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority=priority,
                                hard_timeout=hard_timeout, 
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        

    #検知用のフローエントリを挿入
    def send_flow_mod(self, datapath, priority, idle_timeout, match):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowMod(datapath=datapath, table_id=0, priority=priority, 
                                    idle_timeout=idle_timeout, match=match)
        datapath.send_msg(req)



    #Packet_Inが発生した場合
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):     
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        
        #get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        #self.dp_all.append(datapath)
        self.mac_to_port.setdefault(dpid, {})

        #analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
                
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']
        
        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:    
            return

       # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocols(ipv4.ipv4)[0]
                srcip = ip.src
                dstip = ip.dst
                protoip = ip.proto                
                #self.dpid_block.setdefault(srcip, datapath)
                #print(self.dpid_block)
                
                
                
                #境界に設置されたOpenFlowスイッチの場合
                if dpid == 1:
                    #TCPだったとき
                    if protoip == 6:
                        tcpv4 = pkt.get_protocols(tcp.tcp)[0]
                        tcp_flag = tcpv4.bits
                        layer4_header = pkt.protocols[2]
                        #Now to extract the destination port
                        dst_port = layer4_header.dst_port
                        print('tcp_flag',tcp_flag)
                        if tcp_flag==2 or tcp_flag==10:
                            print('SYN packet')                        
                            if srcip in self.syn_count.keys():
                                self.syn_count[srcip]+=1
                            else:
                                self.syn_count[srcip]=1
                            
                            if(srcip,dstip) not in self.save_comb.keys():
                                if srcip in self.dest_count.keys():
                                    self.dest_count[srcip]+=1
                                else:
                                    self.dest_count[srcip]=1
                                self.save_comb[srcip,dstip] = 1
                                
                                                                      
                    print('組み合わせ',self.save_comb)
                    print('SYN',self.syn_count)
                    print('宛先IPアドレス',self.dest_count)
                    match_openflow = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dstip)
                    self.add_flow(datapath, 1, 200, match_openflow, actions)
                        
                #L2スイッチの場合
                else:
                    #print('l2 switch')
                    match_l2 = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dstip)
                    self.add_flow(datapath, 1, 200, match_l2, actions)
                                                            
        data = None    
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        match = parser.OFPMatch(in_port=in_port)
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out)
        
        
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    #検知
    def _detection(self):
        while True:
            for dp in self.datapaths.values():
                if [k for k, v in self.datapaths.items() if v == dp][0]==1:
                   self.detec(dp)
            print('Check')
            hub.sleep(3)

    def detec(self,datapath):
        print('Check Detection')
        parser = datapath.ofproto_parser
        for src in self.syn_count.keys():
            if self.syn_count[src] >= 10 and self.dest_count[src] >= 5:
                print('検知しました')
                print('srcIP:',src,' syn:',self.syn_count[src],' dest:',self.dest_count[src])
                match5 = parser.OFPMatch(eth_type=0x0800,ipv4_src=src,ip_proto=6)
                if datapath.id==1:
                    self.send_flow_mod(datapath, 100, 100, match5)
            else:
                print('正常です')
                print('srcIP:',src,' syn:',self.syn_count[src],' dest:',self.dest_count[src])
        self.syn_count.clear()
        self.dest_count.clear()
        self.save_comb.clear()
            
        
    