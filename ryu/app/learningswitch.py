# Copyright (C) 2011, Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2014, Georgia Institute of Technology
# Copyright (C) 2014, Beijing University of Posts and Telecommunications
# Copyright (C) 2015, University of Wuerzburg, Germany
#
# Contributors:
#
#    Akshar Rawal (arawal@gatech.edu)
#    Flavio Castro (castro.flaviojr@gmail.com)
#    Logan Blyth (lblyth3@gatech.edu)
#    Matthew Hicks (mhicks34@gatech.edu)
#    Uy Nguyen (unguyen3@gatech.edu)
#    Li Cheng, (http://www.muzixing.com)
#    Steffen Gebert, (http://www3.informatik.uni-wuerzburg.de/staff/steffen.gebert/)
#
# #  To run:
#
#    ryu--manager --observe-links shortestpath.py
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, lldp, tcp, udp
from ryu.lib import mac
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx

class learningswitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(learningswitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called during handshake, defines rule to send all unknown packets to controller

        :type ev: ryu.controller.ofp_event.EventOFPSwitchFeatures
        :return: None
        :rtype: None
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # this rule has to stay forever
        timeout = 0
        # with the lowest priority
        priority = 0
        self.add_flow(datapath, priority, match, actions, timeout, timeout)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=60, hard_timeout=180):
        """
        Pushes a new flow to the datapath (=switch)

        :type datapath: ryu.controller.controller.Datapath
        :type priority: int
        :type match: ryu.ofproto.ofproto_v1_3_parser.OFPMatch
        :type actions: list
        :type idle_timeout: int
        :type hard_timeout: int
        :return: None
        :rtype: None
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Called every time, when the controller receives a PACKET_IN message

        :type ev: ryu.controller.ofp_event.EventOFPPacketIn
        :return: None
        :rtype: None
        """

        # <editor-fold desc="Initialization of couple of variables">
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # create a Packet object out of the payload
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        # source and destination mac address of the ethernet packet
        dst = eth.dst
        src = eth.src

        # DPID is just like the number of the switch
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # </editor-fold>

        # <editor-fold desc="Drop IPv6 Packets">
        if pkt.get_protocol(ipv6.ipv6):
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None
        # </editor-fold>

        # <editor-fold desc="Logging">
        self.logger.info("sw%s: PACKET_IN %s->%s at port %s - %s", dpid, src, dst, in_port, pkt)
        # </editor-fold>

        # <editor-fold desc="Learn sender's MAC address">
        self.mac_to_port[dpid][src] = in_port
        # </editor-fold>

        # <editor-fold desc="Known destination MAC address">
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        # </editor-fold>

        # <editor-fold desc="Unknown destination MAC address">
        else:
            # we don't know anything, so flood the packet
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("sw%s: Flooding", dpid)
        # </editor-fold>

        # <editor-fold desc="Action for the packet_out / flow entry">
        actions = [parser.OFPActionOutput(out_port)]
        # </editor-fold>

        # <editor-fold desc="Install a flow to avoid packet_in next time">
        if out_port != ofproto.OFPP_FLOOD:
            match_fields = {'in_port': in_port, 'eth_dst': eth.dst}
            self.logger.info("Pushing flow rule to sw%s: %s -> port %s", dpid, match_fields, out_port)
            match = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 1, match, actions)
        # </editor-fold>

        # <editor-fold desc="Send PACKET_OUT">
        data = None
        # if the switch has buffered the packet, we don't have to send back the payload
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        # </editor-fold>