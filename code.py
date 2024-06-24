from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
import os
import csv
import time
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()
priority = 50000

l2config = "l2firewall.config"
l3config = "l3firewall.config"

class EnhancedFirewall(EventMixin):

    def __init__(self, l2config, l3config):
        self.listenTo(core.openflow)
        self.disabled_MAC_pair = []
        self.portTable = {}
        self.mac_stats = {}

        if l2config == "":
            l2config = "l2firewall.config"
        if l3config == "":
            l3config = "l3firewall.config"

        with open(l2config, 'rb') as rules:
            csvreader = csv.DictReader(rules)
            for line in csvreader:
                mac_0 = EthAddr(line['mac_0']) if line['mac_0'] != 'any' else None
                mac_1 = EthAddr(line['mac_1']) if line['mac_1'] != 'any' else None
                self.disabled_MAC_pair.append((mac_0, mac_1))

        with open(l3config) as csvfile:
            log.debug("Reading log file!")
            self.rules = csv.DictReader(csvfile)
            for row in self.rules:
                log.debug("Saving individual rule parameters in rule dict!")
                s_ip = row['src_ip']
                d_ip = row['dst_ip']
                s_port = row['src_port']
                d_port = row['dst_port']
                print("src_ip, dst_ip, src_port, dst_port", s_ip, d_ip, s_port, d_port)

        log.debug("Enabling Enhanced Firewall Module")

    def replyToARP(self, packet, match, event):
        r = arp()
        r.opcode = arp.REPLY
        r.hwdst = match.dl_src
        r.protosrc = match.nw_dst
        r.protodst = match.nw_src
        r.hwsrc = match.dl_dst
        e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

    def allowOther(self, event):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        action = of.ofp_action_output(port=of.OFPP_NORMAL)
        msg.actions.append(action)
        event.connection.send(msg)

    def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        if srcip:
            match.nw_src = IPAddr(srcip)
        if dstip:
            match.nw_dst = IPAddr(dstip)
        match.nw_proto = int(nwproto)
        match.dl_src = srcmac
        match.dl_dst = dstmac
        match.tp_src = sport
        match.tp_dst = dport
        match.dl_type = pkt.ethernet.IP_TYPE
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 200
        msg.priority = priority + offset
        event.connection.send(msg)

    def replyToIP(self, packet, match, event, fwconfig):
        srcmac = str(match.dl_src)
        dstmac = str(match.dl_src)
        sport = str(match.tp_src)
        dport = str(match.tp_dst)
        nwproto = str(match.nw_proto)

        with open(l3config) as csvfile:
            log.debug("Reading log file!")
            self.rules = csv.DictReader(csvfile)
            for row in self.rules:
                prio = row['priority']
                srcmac = row['src_mac']
                dstmac = row['dst_mac']
                s_ip = row['src_ip']
                d_ip = row['dst_ip']
                s_port = row['src_port']
                d_port = row['dst_port']
                nw_proto = row['nw_proto']

                log.debug("You are in the original code block...")
                srcmac1 = EthAddr(srcmac) if srcmac != 'any' else None
                dstmac1 = EthAddr(dstmac) if dstmac != 'any' else None
                s_ip1 = s_ip if s_ip != 'any' else None
                d_ip1 = d_ip if d_ip != 'any' else None
                s_port1 = int(s_port) if s_port != 'any' else None
                d_port1 = int(d_port) if d_port != 'any' else None
                prio1 = int(prio) if prio else priority
                if nw_proto == "tcp":
                    nw_proto1 = pkt.ipv4.TCP_PROTOCOL
                elif nw_proto == "icmp":
                    nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
                    s_port1 = None
                    d_port1 = None
                elif nw_proto == "udp":
                    nw_proto1 = pkt.ipv4.UDP_PROTOCOL
                else:
                    log.debug("PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP")
                print(prio1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
                self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
        self.allowOther(event)

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection

        for (source, destination) in self.disabled_MAC_pair:
            print(source, destination)
            message = of.ofp_flow_mod()
            match = of.ofp_match()
            match.dl_src = source
            match.dl_dst = destination
            message.priority = 65535
            message.match = match
            event.connection.send(message)

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        match = of.ofp_match.from_packet(packet)

        if match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST:
            self.replyToARP(packet, match, event)

        if match.dl_type == packet.IP_TYPE:
            ip_packet = packet.payload

            if packet.src not in self.portTable.keys():
                self.portTable[packet.src] = packet.next.srcip
            elif self.portTable[packet.src] != packet.next.srcip:
                if (packet.src, None) not in self.disabled_MAC_pair:
                    self.disabled_MAC_pair.append((packet.src, None))
                    self._handle_ConnectionUp(event)

            print("Ip_packet.protocol =", ip_packet.protocol)
            if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
                log.debug("TCP it is!")

            self.replyToIP(packet, match, event, self.rules)


def launch(l2config="l2firewall.config", l3config="l3firewall.config"):
    parser = argparse.ArgumentParser()
    parser.add_argument('--l2config', action='store', dest='l2config',
                        help='Layer 2 config file', default='l2firewall.config')
    parser.add_argument('--l3config', action='store', dest='l3config',
                        help='Layer 3 config file', default='l3firewall.config')
    core.registerNew(EnhancedFirewall, l2config, l3config)
