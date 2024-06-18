from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0

class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg 
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
###		ev.msg : representing a packeet_in data structure
###		msg.dp : representing a datapath(switch)
###		dp.ofproto & dp.ofproto_parser : representing the OpenFlow protocol that Ryu and the switch negotiated
		
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
		
### 	OFPActionOutput : packet_out message to specify a switch port
###		OFPP_FLOOD : all port
		

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
             data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = data)
		
###		OFPPacketOut : building a packet_out message
		
        dp.send_msg(out)
