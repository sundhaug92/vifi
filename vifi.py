from scapy.all import *
# from scapy.layers.tls.all import *
from sys import argv
from py2neo.database import Graph, Node, Relationship
import re
import os.path
# import pdb

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
known_connections = []


def register_connection(connection_type, at_time, from_node_name, to_node_name):
    global known_connections
    for _ in ['', '\0', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']:
        if _ in [from_node_name, to_node_name]: return
    for name in [from_node_name, to_node_name]:
        if re.search(r'([0-9a-f]{2}[:]){5}([0-9a-f]{2})', name) and (name.lower()[1] in ['2', '6', 'a', 'e'] or name.startswith('33:33:')):
            return
    if (connection_type, from_node_name, to_node_name) in known_connections:
        return
#    print(at_time, connection_type, from_node_name, to_node_name)
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
    else:
        raise Exception('Unknown connection type {}'.format(connection_type))
    rel = Relationship(from_node, connection_type, to_node)
    for n in [to_node, from_node, rel]:
        if type(n) is Relationship:
            tx.merge(n)
            continue
        if n.has_label('device'):
            tx.merge(n, primary_key='mac_address')
        elif n.has_label('network'):
            tx.merge(n, primary_key='essid')
    tx.commit()
    known_connections.append((connection_type, from_node_name, to_node_name))
    known_connections = known_connections[-10000:]


def pktInfoDecodeable(pkt):
    try:
        pkt.info.decode()
        return True
    except:
        return False

def PacketHandler(pkt):
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
        if pkt.haslayer(EAP):
            eap = pkt.getlayer(EAP)
            if eap.code == 1:  # EAP code=request
                if eap.type == 1:  # EAP type=identity
                    register_connection('EAP/IDENTITY/SENT_REQUEST', pkt.time, pkt.addr2, pkt.addr1)
            elif eap.code == 2: # EAP code=response
                if eap.type == 1: # EAP type=identity
                    register_connection('EAP/IDENTITY/RESPONSE', pkt.time, pkt.addr2, eap.identity.decode())
                    register_connection('EAP/IDENTITY/SENT_RESPONSE', pkt.time, pkt.addr2, pkt.addr1)
                    register_connection('EAP/IDENTITY/RECV_RESPONSE', pkt.time, eap.identity.decode(), pkt.addr1)


print('Connecting to graph')
graph = Graph(password='password') # TODO: parameterize, don't hardcode password


interfaces = []
sniff_args = {
    'store': 0,
    'prn': PacketHandler,
    'lfilter': lambda x: x.haslayer(Dot11)
}

for filename in argv[1:]:
    if os.path.isfile(filename):
        print('Loading from file', filename)
        sniff(offline=filename, **sniff_args)
    else:
        print('Will sniff from interface',filename)
        interfaces.append(filename)

if interfaces == [] and argv[1:] == []:
    interfaces = None
    print('Will sniff on all interfaces, might break')
    sniff(iface=interfaces, **sniff_args)
elif interfaces != []:
    print('Will sniff on', ', '.join(interfaces))
    sniff(iface=interfaces, **sniff_args)
