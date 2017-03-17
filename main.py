from scapy.all import *
from xml.sax.saxutils import escape

assoc_list = []
nodes = []
edge_count = 1

def PacketHandler(pkt):
    global assoc_list, nodes, edge_count
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 4 and pkt.info != '':
            probed_ssid = escape(pkt.info)
            probing_mac = escape(pkt.addr2)
            if probed_ssid != pkt.info:
                return #Hack
            if probed_ssid not in nodes:
                nodes.append(probed_ssid)
            if probing_mac not in nodes:
                nodes.append(probing_mac)
            if (probing_mac, probed_ssid) not in assoc_list:
                assoc_list.append((probing_mac, probed_ssid))
                edge_count += 1

sniff(iface="rename7", prn = PacketHandler)
