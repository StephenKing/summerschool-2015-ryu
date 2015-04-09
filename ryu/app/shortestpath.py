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

class MultipathForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MultipathForwarding, self).__init__(*args, **kwargs)
        self.arp_table = {}
        self.sw = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()

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
        if src not in self.net:
            # we received a packet from a MAC address that we've never seen
            # TODO add new learned MAC to our network graph

            # TODO remember to which port of the switch (dpid) this MAC is attached

            self.net_updated()
        # </editor-fold>

        # <editor-fold desc="Know destination MAC address">
        if dst in self.net:
            # compute the shortest path to the destination
            # TODO path =

            # specify out_port, find the switch port, where the next switch is connected
            # TODO out_port =

            self.logger.info("Path %s -> %s via %s", src, dst, path)
        # </editor-fold>

        # <editor-fold desc="Unknown destination MAC address">
        else:
            # TODO flooding is not always good, isn't it?

            # we don't know anything, so flood the packet
            out_port = ofproto.OFPP_FLOOD
        # </editor-fold>

        # <editor-fold desc="Action for the packet_out / flow entry">
        actions = [parser.OFPActionOutput(out_port)]
        # </editor-fold>

        # <editor-fold desc="Install a flow to avoid packet_in next time">
        if out_port != ofproto.OFPP_FLOOD:
            # generate a pretty precise match
            match_fields = self.get_match_l4(msg)
            self.logger.info("Pushing flow rule to sw%s: %s", dpid, match_fields)
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

    def arp_handler(self, msg):
        """
        Handles ARP messages for us, avoids broadcast storms

        :type msg: ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn
        :return: True, if the ARP was handeled, False otherwise
        :rtype: bool
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip

            if (datapath.id, eth_src, arp_dst_ip) in self.sw:
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        # Try to reply arp request
        if arp_pkt:
            opcode = arp_pkt.opcode
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()

                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    arp_reply.serialize()

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    self.logger.info("Replied to ARP request for %s with %s", arp_dst_ip, self.arp_table[arp_dst_ip])
                    return True
        return False

    @set_ev_cls(event.EventSwitchEnter)
    def update_topology(self, ev):
        """
        Watches the topology for updates (new switches/links)
        :type ev:ryu.topology.event.EventSwitchEnter
        :return: None
        :rtype: None
        """
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)

        self.net_updated()

    def net_updated(self):
        """
        Things we want to do, when the topology changes
        :return: None
        :rtype: None
        """
        self.logger.info("Links: %s", self.net.edges())

    def get_match_l4(self, msg):
        """
        Define the match to match packets up to Layer 4 (TCP/UDP ports)

        :param msg: The message to process
        :type msg: ryu.controller.ofp_event.EventOFPMsgBase
        :return: Dictionary containing matching fields
        :rtype: dict
        """
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        match_fields = dict()
        match_fields['in_port'] = in_port
        match_fields['eth_dst'] = eth.dst
        match_fields['eth_type'] = eth.ethertype

        # we try to parse this as IPv4 packet
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        ###############################
        # TODO continue here to match up to TCP ports
        ###############################
        # define matches for particular header fields to specify more fine-grained rules

        # match fields defined in type : ryu.ofproto.ofproto_v1_3_parser.OFPMatch
        # https://github.com/osrg/ryu/blob/72a06f6f60dafd3c246d27477b0c3261ba9c061c/ryu/ofproto/ofproto_v1_3_parser.py#L689-L732

        # eth/ipv4/tcp/udp etc. classes in ryu.lib.packet
        # https://github.com/osrg/ryu/tree/72a06f6f60dafd3c246d27477b0c3261ba9c061c/ryu/lib/packet

        return match_fields
