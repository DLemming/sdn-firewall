from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, ipv6, ether_types, icmp

class SimpleFirewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.rules = [
            # only allow traffic from h1 to h3
            {'src_ip': "10.0.0.1", 'dst_ip': "10.0.0.3", 'dst_port': "any", 'src_port': "any"},
        ]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry (sends unmatched packets to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Add a flow entry to the switch.

        Args:
            datapath: The OpenFlow switch.
            priority: The priority of the flow entry.
            match: The match criteria for the flow entry.
            actions: The actions to be performed on matching packets.
            buffer_id: The buffer ID of the packet (if applicable).

        Returns:
            None
        """
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=instructions)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=instructions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        # Fetch all the information from the event
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        ### Ignore LLDP ###
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.info("[LLDP] Ignoring...")
            return
        
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            self.logger.info("[IPv6] Ignoring...")
            return

        ### Handle ARP ###
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info(f"[ARP] Handling: %s to %s", src, dst)

            self.handle_packet(msg, eth_type=0x0806)
            return
        
        ### Handle ICMP ###
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if ip_pkt and icmp_pkt:
            self.logger.info("[ICMP] Handling: %s to %s)", ip_pkt.src, ip_pkt.dst)

            self.ip_to_port.setdefault(dpid, {})
            self.ip_to_port[dpid][ip_pkt.src] = in_port # learn IP @ port
            self.handle_packet(msg, eth_type=0x0800, ip_proto=0x01)
            return
        
        ### Parse Firewall Rules ###
        priority=10
        for rule in self.rules:
            match_args = {'eth_type': 0x0800, 'ip_proto': 0x06}  # Default Ethernet and TCP

            if rule["src_ip"] != "any":
                match_args['ipv4_src'] = rule['src_ip']
            if rule['dst_ip'] != "any":
                match_args['ipv4_dst'] = rule['dst_ip']
            if rule['src_port'] != "any":
                match_args['tcp_src'] = int(rule['src_port'])
            if rule['dst_port'] != "any":
                match_args['tcp_dst'] = int(rule['dst_port'])

            match = parser.OFPMatch(**match_args)

            # Reverse match (for bidirectional rules)
            match_rev_args = match_args.copy()
            if 'ipv4_src' in match_args and 'ipv4_dst' in match_args:
                match_rev_args['ipv4_src'], match_rev_args['ipv4_dst'] = match_args['ipv4_dst'], match_args['ipv4_src']
            if 'tcp_src' in match_args and 'tcp_dst' in match_args:
                match_rev_args['tcp_src'], match_rev_args['tcp_dst'] = match_args['tcp_dst'], match_args['tcp_src']
            
            match_rev = parser.OFPMatch(**match_rev_args)

            #print(f"Match: {match}")
            #print(f"Reverse Match: {match_rev}")

            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            #self.logger.info("Adding Flows for Forward Flow")
            self.add_flow(datapath, priority, match, actions)
            priority += 1

            actions_rev = [parser.OFPActionOutput(out_port)]
            #self.logger.info("Adding Flows for Reverse Flow")
            self.add_flow(datapath, priority, match_rev, actions_rev)
            priority += 1

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            #print("Sending PacketOut message")
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        # Log dropped packets that don't match any firewall rule
        self.logger.info(f"[DROP] No matching firewall rule. Dropping {eth.ethertype} traffic.")
        self.logger.info(f"    SRC MAC: {eth.src}, DST MAC: {eth.dst}")
        if ip_pkt:
            self.logger.info(f"    SRC IP: {ip_pkt.src}, DST IP: {ip_pkt.dst}")


        # Drop TCP traffic (if no firewall rule matched)
        #self.logger.info("[TCP] dropped!")
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06)  # TCP traffic
        mod = parser.OFPFlowMod(datapath=datapath, priority=5,
                                command=ofproto.OFPFC_ADD, match=match, instructions=[])
        datapath.send_msg(mod)

        # Drop UDP traffic (if no firewall rule matched)
        #self.logger.info("[UDP] dropped!")
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x17)  # UDP traffic
        mod = parser.OFPFlowMod(datapath=datapath, priority=4,
                                command=ofproto.OFPFC_ADD, match=match, instructions=[])
        datapath.send_msg(mod)

        # Forward all traffic (Default Allow Policy)
        #actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        #match = parser.OFPMatch(eth_src=src, eth_dst=dst)
        #self.add_flow(datapath, 1, match, actions)
        
        #out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                          in_port=in_port, actions=actions,
        #                          data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        #datapath.send_msg(out)

    def handle_packet(self, msg, eth_type, ip_proto=None):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {}) # sets default value of mac_to_port to an empty dictionary, if not already exists
        self.mac_to_port[dpid][eth.src] = in_port
        
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        match_args = {'in_port': in_port, 'eth_dst': eth.dst, 'eth_type': eth_type}
        if ip_proto is not None:
            match_args['ip_proto'] = ip_proto
        match = parser.OFPMatch(**match_args)

        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 2, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 2, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)