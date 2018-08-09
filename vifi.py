#!/usr/bin/env python3
from scapy.all import *
from sys import argv
from py2neo import remote
from py2neo.database import Graph, Node, Relationship
import re
import os.path
import logging

known_packet_types = []
pkt_desc = {
    0: {
        'name': 'MGMT',
        0: 'ASSOC REQUEST',
        1: 'ASSOC RESPONSE',
        2: 'RESSOC REQUEST',
        3: 'REASSOC RESPONSE',
        4: 'PROBE_REQUEST',
        5: 'PROBE_RESPONSE',
        8: 'BEACON',
        9: 'ATIM',
        11: 'DISASSOC',
        12: 'AUTH',
        13: 'DEAUTH'
    },
    1: {
        'name': 'CTRL',
        10: 'PS-POLL',
        11: 'RTS',
        12: 'CTS',
        13: 'ACK'
    },
    2: {
        'name': 'DATA',
        0: 'DATA',
        1: 'DATA + CF-ACK',
        2: 'DATA + CF-POLL',
        3: 'DATA + CF-ACK + CF-POLL',
        4: 'NULL FUNCTION'
    }
}

graph = None
known_relationships = {}

def handle_known_relationships_count(tx, max_count):
    if len(known_relationships) > max_count:
        logger.debug('Flushing', len(known_relationships) - max_count, 'relationships')
    while len(known_relationships) > max_count:
        k = list(known_relationships.keys())[0]
        v = known_relationships[k]
        (id1, rel_type, id2) = v['rel']
        rel = tx.match_one(graph.node(id1), rel_type, graph.node(id2))
        if rel['first_seen'] is None or rel['first_seen'] > v['first_seen']:
            rel['first_seen'] = v['first_seen']
        if rel['last_seen'] is None or rel['last_seen'] < v['last_seen']:
            rel['last_seen'] = v['last_seen']
        if rel['times'] is None:
            rel['times'] = 0
        rel['times'] += v['times']
        rel.push()
        for n in rel.nodes():
            if n['first_seen'] is None or n['first_seen'] > v['first_seen']:
                n['first_seen'] = v['first_seen']
            if n['last_seen'] is None or n['last_seen'] < v['last_seen']:
                n['last_seen'] = v['last_seen']
            if n['times'] is None:
                n['times'] = 0
            n['times'] += v['times']
            tx.push(n)
        del known_relationships[k]


def register_connection(connection_type, at_time, from_node_name, to_node_name):
    global known_relationships
    for _ in ['', '\0', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']:
        if _ in [from_node_name, to_node_name]: return
    for name in [from_node_name, to_node_name]:
        if re.search(r'([0-9a-f]{2}[:]){5}([0-9a-f]{2})', name) and (name.lower()[1] in ['2', '6', 'a', 'e'] or name.startswith('33:33:')):
            return
    if (connection_type, from_node_name, to_node_name) in known_relationships.keys():
        v = known_relationships[(connection_type, from_node_name, to_node_name)]
        if v['first_seen'] > at_time:
            v['first_seen'] = at_time
        if v['last_seen'] < at_time:
            v['last_seen'] = at_time
        v['times'] += 1
        return
    from_node = None
    to_node = None
    tx = graph.begin()
    if connection_type in ['WIFI/MGMT/BEACON', 'WIFI/MGMT/PROBE_REQUEST', 'WIFI/MGMT/PROBE_RESPONSE/MAC_SENT_SSID']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('network', essid=to_node_name)
    elif connection_type in ['WIFI/MGMT/PROBE_RESPONSE/MAC_RECV_SSID']:
        from_node = Node('network', essid=from_node_name)
        to_node = Node('device', mac_address=to_node_name)
    elif connection_type in ['WIFI/CTRL/ACK', 'ETHER/GEN/MAC_TO_MAC', 'EAP/IDENTITY/SENT_RESPONSE', 'EAP/IDENTITY/SENT_REQUEST']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('device', mac_address=to_node_name)
    elif connection_type in ['EAP/IDENTITY/RESPONSE']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('identity', identity=to_node_name)
    elif connection_type in ['EAP/IDENTITY/RECV_RESPONSE']:
        from_node = Node('identity', identity=from_node_name)
        to_node = Node('device', mac_address=to_node_name)
    elif connection_type in ['ARP/IS_AT', 'ARP/WHO_HAS', 'DHCP/ACK/ROUTER', 'DHCP/ACK/NAME_SERVER', 'DHCP/OFFER/ROUTER', 'DHCP/OFFER/NAME_SERVER', 'BOOTP/YIADDR']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('ip', ip=to_node_name)
    elif connection_type in ['DHCP/DISCOVER/HOSTNAME', 'DHCP/ACK/DOMAIN', 'DHCP/OFFER/DOMAIN']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('hostname', hostname=to_node_name)
    elif connection_type in ['IP/PORT']:
        from_node = Node('ip', ip_address=from_node_name)
        to_node = Node('ip_port', port_name=to_node_name)
    elif connection_type in ['IP/PORT/TRAFFIC']:
        from_node = Node('ip_port', port_name=from_node_name)
        to_node = Node('ip_port', port_name=to_node_name)
    elif connection_type in ['IP/TRAFFIC']:
        from_node = Node('ip', ip_address=from_node_name)
        to_node = Node('ip', ip_address=to_node_name)
    if from_node is None or to_node is None:
        logger.debug('connection_type', connection_type, 'from_node_name', from_node_name, 'from_node', from_node, 'to_node_name', to_node_name, 'to_node', to_node)
        raise Exception('Unknown connection type {}'.format(connection_type))
    rel = Relationship(from_node, connection_type, to_node)
    for n in [to_node, from_node, rel]:
        tx.merge(n)
    tx.commit()
    logger.debug(to_node, from_node, rel)
    known_relationships[(connection_type, from_node_name, to_node_name)] = {
        'times': 1,
        'first_seen': at_time,
        'last_seen': at_time,
        'rel': (remote(from_node)._id, connection_type, remote(to_node)._id)
    }
    handle_known_relationships_count(tx, max_count=10000)


def pktInfoDecodeable(pkt):
    try:
        pkt.info.decode()
        return True
    except:
        return False


def do_dpi(pkt):
    if pkt.haslayer(EAP):
        eap = pkt.getlayer(EAP)
        if eap.code == 1:  # EAP code=request
            if eap.type == 1:  # EAP type=identity
                register_connection('EAP/IDENTITY/SENT_REQUEST', pkt.time, pkt.addr2, pkt.addr1)
            else:
                logger.debug('Unknown EAP type', eap.code, eap.type)
        elif eap.code == 2:  # EAP code=response
            if eap.type == 1:  # EAP type=identity
                register_connection('EAP/IDENTITY/RESPONSE', pkt.time, pkt.addr2, eap.identity.decode())
                register_connection('EAP/IDENTITY/SENT_RESPONSE', pkt.time, pkt.addr2, pkt.addr1)
                register_connection('EAP/IDENTITY/RECV_RESPONSE', pkt.time, eap.identity.decode(), pkt.addr1)
            else:
                logger.debug('Unknown EAP type', eap.code, eap.type)
        else:
            logger.debug('DEBUG: Unknown EAP code', eap.code)
    elif pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        port_type = 'ERROR'
        if pkt.haslayer(UDP):
            port_type = 'udp'
        elif pkt.haslayer(TCP):
            port_type = 'tcp'
        if port_type != 'ERROR':
            sport, dport = ip.sport, ip.dport
            src_port_name = (ip.src if ip.version == 4 else '[' + str(ip.src) + ']') + ':' + str(sport) + '/' + port_type
            dst_port_name = (ip.dst if ip.version == 4 else '[' + str(ip.dst) + ']') + ':' + str(dport) + '/' + port_type
            register_connection('IP/PORT', pkt.time, ip.src, src_port_name)
            register_connection('IP/PORT', pkt.time, ip.dst, dst_port_name)
            register_connection('IP/PORT/TRAFFIC', pkt.time, src_port_name, dst_port_name)
        if pkt.haslayer(ARP):
            arp = pkt.getlayer(ARP)
            if arp.op == arp.is_at:
                register_connection('ARP/IS_AT', pkt.time, arp.hwsrc, arp.psrc)
            elif arp.op == arp.who_has:
                register_connection('ARP/WHO_HAS', pkt.time, arp.hwsrc, arp.pdst)
        elif pkt.haslayer(DHCP):
            bootp = pkt.getlayer(BOOTP)
            dhcp = pkt.getlayer(DHCP)
            options = {}
            for option in dhcp.options:
                if option in ['end', 'pad']:
                    continue
                options[option[0]] = option[1:]
            options['message-type']=options['message-type'][0]
            if options['message-type'] == 1:  # DISCOVER
                # TODO: Use option 61 if available instead of pkt.addr2
                if 'hostname' in options.keys():
                    register_connection('DHCP/DISCOVER/HOSTNAME', pkt.time, pkt.addr2, options['hostname'][0].decode())
            elif options['message-type'] == 2:  # OFFER
                register_connection('BOOTP/YIADDR', pkt.time, pkt.addr1, bootp.yiaddr)
                if 'router' in options.keys():
                    for router in options['router']:
                        register_connection('DHCP/OFFER/ROUTER', pkt.time, pkt.addr1, router)
                if 'name_server' in options.keys():
                    for name_server in options['name_server']:
                        register_connection('DHCP/OFFER/NAME_SERVER', pkt.time, pkt.addr1, name_server)
                if 'domain' in options.keys():
                    for domain in options['domain']:
                        register_connection('DHCP/OFFER/DOMAIN', pkt.time, pkt.addr1, domain.decode().replace('\x00', ''))
            elif options['message-type'] == 5:  # ACK
                register_connection('BOOTP/YIADDR', pkt.time, pkt.addr2, bootp.yiaddr)
                if 'router' in options.keys():
                    for router in options['router']:
                        register_connection('DHCP/ACK/ROUTER', pkt.time, pkt.addr2, router)
                if 'name_server' in options.keys():
                    for name_server in options['name_server']:
                        register_connection('DHCP/ACK/NAME_SERVER', pkt.time, pkt.addr2, name_server)
                if 'domain' in options.keys():
                    for domain in options['domain']:
                        register_connection('DHCP/ACK/DOMAIN', pkt.time, pkt.addr2, domain.decode().replace('\x00', ''))
            else:
                logger.debug('DHCP unknown message-type', options['message-type'])


def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0:
            if pkt.subtype == 4:
                if not pktInfoDecodeable(pkt):
                    return
                register_connection('WIFI/MGMT/PROBE_REQUEST', pkt.time, pkt.addr2, pkt.info.decode())
            elif pkt.subtype == 5:
                if not pktInfoDecodeable(pkt):
                    return
                register_connection('WIFI/MGMT/PROBE_RESPONSE/MAC_RECV_SSID', pkt.time, pkt.info.decode(), pkt.addr1)
                register_connection('WIFI/MGMT/PROBE_RESPONSE/MAC_SENT_SSID', pkt.time, pkt.addr3, pkt.info.decode())
                register_connection('ETHER/GEN/MAC_TO_MAC', pkt.time, pkt.addr3, pkt.addr1)
            elif pkt.subtype == 8:
                if not pktInfoDecodeable(pkt):
                    return
                register_connection('WIFI/MGMT/BEACON', pkt.time, pkt.addr2, pkt.info.decode())
        elif pkt.type == 2:
            # TODO: Find out who sends what to whom, add ETHER/GEN/MAC_TO_MAC
            do_dpi(pkt)
    else:
        do_dpi(pkt)


logger = logging.getLogger()
print('Connecting to graph')
graph = Graph(password='password')  # TODO: parameterize, don't hardcode password


interfaces = []
sniff_args = {
    'store': 0,
    'prn': PacketHandler
}

for filename in argv[1:]:
    if os.path.isfile(filename):
        print('Loading from file', filename)
        sniff(offline=filename, **sniff_args)
    else:
        print('Will sniff from interface', filename)
        interfaces.append(filename)
handle_known_relationships_count(0, graph.begin())

if interfaces == [] and argv[1:] == []:
    interfaces = None
    print('Will sniff on all interfaces, might break')
    sniff(iface=interfaces, **sniff_args)
elif interfaces != []:
    print('Will sniff on', ', '.join(interfaces))
    sniff(iface=interfaces, **sniff_args)
