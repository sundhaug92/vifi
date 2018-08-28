#!/usr/bin/env python3
import logging
import os.path
import re
import time
from multiprocessing import Process, JoinableQueue, cpu_count
from sys import argv
from os import nice
import pdb

from py2neo import remote
from py2neo.database import Graph, Node, Relationship

from scapy.all import *
from scapy_http.http import *

graph = None


def get_connection(connection_type, from_node_name, to_node_name):
    for _ in ['', '\0', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']:
        if _ in [from_node_name, to_node_name]:
            return
    for name in [from_node_name, to_node_name]:
        if re.search(r'([0-9a-f]{2}[:]){5}([0-9a-f]{2})', name) and (name.lower()[1] in ['2', '6', 'a', 'e'] or name.startswith('33:33:')):
            return
    from_node = None
    to_node = None
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
    elif connection_type in ['ARP/IS_AT', 'ARP/WHO_HAS', 'DHCP/ACK/ROUTER', 'DHCP/ACK/NAME_SERVER', 'DHCP/OFFER/ROUTER', 'DHCP/OFFER/NAME_SERVER', 'BOOTP/YIADDR', 'ETHER/IP/TRANSMITS_IP', 'ETHER/IP/RECEIVES_IP']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('ip', ip_address=to_node_name)
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
    elif connection_type in ['HTTP/REQUEST/HOST', 'HTTP/RESPONSE/HOST']:
        from_node = Node('ip', ip_address=from_node_name)
        to_node = Node('hostname', hostname=to_node_name)
    elif connection_type in ['HTTP/REQUEST/USER_AGENT']:
        from_node = Node('ip', ip_address=from_node_name)
        to_node = Node('useragent', ua_string=to_node_name)
    if from_node is None or to_node is None:
        logger.debug('connection_type', connection_type, 'from_node_name', from_node_name, 'from_node', from_node, 'to_node_name', to_node_name, 'to_node', to_node)
        raise Exception('Unknown connection type {}'.format(connection_type))
    rel = Relationship(from_node, connection_type, to_node)
    return rel

def register_connection(connection):
    if connection is None:
        raise Exception()
    graph.merge(connection)

def pktInfoDecodeable(pkt):
    try:
        pkt.info.decode()
        return True
    except:
        return False


def do_dpi(pkt):
    connections = []
    if pkt.haslayer(EAP):
        eap = pkt.getlayer(EAP)
        if eap.code == 1:  # EAP code=request
            if eap.type == 1:  # EAP type=identity
                connections.append(('EAP/IDENTITY/SENT_REQUEST', pkt.addr2, pkt.addr1))
            else:
                logger.debug('Unknown EAP type', eap.code, eap.type)
        elif eap.code == 2:  # EAP code=response
            if eap.type == 1:  # EAP type=identity
                connections.append(('EAP/IDENTITY/RESPONSE', pkt.addr2, eap.identity.decode()))
                connections.append(('EAP/IDENTITY/SENT_RESPONSE', pkt.addr2, pkt.addr1))
                connections.append(('EAP/IDENTITY/RECV_RESPONSE', eap.identity.decode(), pkt.addr1))
            else:
                logger.debug('Unknown EAP type', eap.code, eap.type)
        else:
            logger.debug('DEBUG: Unknown EAP code', eap.code)
    elif pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        connections.append(('ETHER/IP/TRANSMITS_IP', pkt.addr2, ip.src))
        connections.append(('ETHER/IP/RECEIVES_IP', pkt.addr1, ip.dst))
        port_type = 'ERROR'
        if pkt.haslayer(UDP):
            port_type = 'udp'
            if pkt.haslayer(DHCP):
                bootp = pkt.getlayer(BOOTP)
                dhcp = pkt.getlayer(DHCP)
                options = {}
                for option in dhcp.options:
                    if option in ['end', 'pad']:
                        continue
                    options[option[0]] = option[1:]
                options['message-type'] = options['message-type'][0]
                if options['message-type'] == 1:  # DISCOVER
                    # TODO: Use option 61 if available instead of pkt.addr2
                    if 'hostname' in options.keys():
                        connections.append(('DHCP/DISCOVER/HOSTNAME', pkt.addr2, options['hostname'][0].decode()))
                elif options['message-type'] == 2:  # OFFER
                    connections.append(('BOOTP/YIADDR', pkt.addr1, bootp.yiaddr))
                    if 'router' in options.keys():
                        for router in options['router']:
                            connections.append(('DHCP/OFFER/ROUTER', pkt.addr1, router))
                    if 'name_server' in options.keys():
                        for name_server in options['name_server']:
                            connections.append(('DHCP/OFFER/NAME_SERVER', pkt.addr1, name_server))
                    if 'domain' in options.keys():
                        for domain in options['domain']:
                            connections.append(('DHCP/OFFER/DOMAIN', pkt.addr1, domain.decode().replace('\x00', '')))
                elif options['message-type'] == 5:  # ACK
                    connections.append(('BOOTP/YIADDR', pkt.addr2, bootp.yiaddr))
                    if 'router' in options.keys():
                        for router in options['router']:
                            connections.append(('DHCP/ACK/ROUTER', pkt.addr2, router))
                    if 'name_server' in options.keys():
                        for name_server in options['name_server']:
                            connections.append(('DHCP/ACK/NAME_SERVER', pkt.addr2, name_server))
                    if 'domain' in options.keys():
                        for domain in options['domain']:
                            connections.append(('DHCP/ACK/DOMAIN', pkt.addr2, domain.decode().replace('\x00', '')))
                else:
                    logger.debug('DHCP unknown message-type', options['message-type'])
        elif pkt.haslayer(TCP):
            port_type = 'tcp'
        if port_type != 'ERROR':
            src_port_name = (ip.src if ip.version == 4 else '[' + str(ip.src) + ']') + ':' + str(ip.sport) + '/' + port_type
            dst_port_name = (ip.dst if ip.version == 4 else '[' + str(ip.dst) + ']') + ':' + str(ip.dport) + '/' + port_type
            connections.append(('IP/PORT', ip.src, src_port_name))
            connections.append(('IP/PORT', ip.dst, dst_port_name))
            connections.append(('IP/PORT/TRAFFIC', src_port_name, dst_port_name))
            if pkt.haslayer(HTTP):
                http = pkt.getlayer(HTTP)
                if pkt.haslayer(HTTPResponse):
                    http_response = http.getlayer(HTTPResponse)
                    if 'Host' in http_response.fields:
                        connections.append(('HTTP/RESPONSE/HOST', ip.src, http_response.fields['Host'].decode()))
                elif pkt.haslayer(HTTPRequest):
                    http_request = http.getlayer(HTTPRequest)
                    if 'Host' in http_request.fields:
                        connections.append(('HTTP/REQUEST/HOST', ip.src, http_request.fields['Host'].decode()))
                    if 'User-Agent' in http_request.fields:
                        connections.append(('HTTP/REQUEST/USER_AGENT', ip.src, http_request.fields['User-Agent'].decode()))
    elif pkt.haslayer(ARP):
        arp = pkt.getlayer(ARP)
        if arp.op == arp.is_at:
            connections.append(('ARP/IS_AT', arp.hwsrc, arp.psrc))
        elif arp.op == arp.who_has:
            connections.append(('ARP/WHO_HAS', arp.hwsrc, arp.pdst))
    return connections


def PacketHandler(pkt):
    connections = []
    if pkt.haslayer(Dot11):
        if pkt.type == 0:
            if pkt.subtype == 4:
                if not pktInfoDecodeable(pkt):
                    return
                connections.append(('WIFI/MGMT/PROBE_REQUEST', pkt.addr2, pkt.info.decode()))
            elif pkt.subtype == 5:
                if not pktInfoDecodeable(pkt):
                    return
                connections.append(('WIFI/MGMT/PROBE_RESPONSE/MAC_RECV_SSID', pkt.info.decode(), pkt.addr1))
                connections.append(('WIFI/MGMT/PROBE_RESPONSE/MAC_SENT_SSID', pkt.addr3, pkt.info.decode()))
                connections.append(('ETHER/GEN/MAC_TO_MAC', pkt.addr3, pkt.addr1))
            elif pkt.subtype == 8:
                if not pktInfoDecodeable(pkt):
                    return
                connections.append(('WIFI/MGMT/BEACON', pkt.addr2, pkt.info.decode()))
        elif pkt.type == 2:
            # TODO: Find out who sends what to whom, add ETHER/GEN/MAC_TO_MAC
            connections += do_dpi(pkt)
    else:
        connections += do_dpi(pkt)
    return connections

def sniffer(sniffer_queue, db_queue):
    nice(1)  # Be a little nicer than the DB-thread
    prev_rels = []
    rel_meta = {}
    def purge_rel_meta():
        nonlocal prev_rels, rel_meta
        for rel in prev_rels:
            db_queue.put(('update_rel', (rel, rel_meta[rel])))
        rel_meta = {}
        prev_rels = []
    while True:
        job = sniffer_queue.get()
        if job is None:
            break
        frame_count = 0

        def _sniffer(rels, pkt):
            nonlocal frame_count, prev_rels, rel_meta
            frame_count += 1
            if rels is not None:
                for rel in rels:
                    if rel is None:
                        continue
                    if rel not in prev_rels:
                        db_queue.put(('new_rel', rel))
                        prev_rels.append(rel)
                        rel_meta[rel] = {
                            'times': 1,
                            'first_seen': pkt.time,
                            'last_seen': pkt.time
                            }
                    else:
                        rel_meta[rel]['times'] += 1
                        if pkt.time < rel_meta[rel]['first_seen']:
                            rel_meta[rel]['first_seen'] = pkt.time
                        elif pkt.time > rel_meta[rel]['last_seen']:
                            rel_meta[rel]['last_seen'] = pkt.time
            if (frame_count % 100000) == 0:
                purge_rel_meta()


        start_time = time.time()
        if job == '*':
            sniff(store=0, prn=lambda p: _sniffer(PacketHandler(p), p))
        elif os.path.isfile(job):
            sniff(offline=job, store=0, prn=lambda p: _sniffer(PacketHandler(p), p))
        else:
            sniff(iface=job, store=0, prn=lambda p: _sniffer(PacketHandler(p), p))
        end_time = time.time()
        sniffer_queue.task_done()
    purge_rel_meta()
    db_queue.put(None)


def db_worker(top_count, db_queue):
    existing_rels = []
    while True:
        try:
            job = db_queue.get()
            if job is None:
                top_count -= 1
                if top_count == 0:
                    break
            else:
                job_type, job_value = job
                if job_type == 'new_rel':
                    if job_value in existing_rels:
                        continue
                    existing_rels.append(job_value)
                    existing_rels = existing_rels[-100000:]
                    register_connection(get_connection(*job_value))
                elif job_type == 'update_rel':
                    pass
                else:
                    raise Exception('Unknown job_type', job_type)
            db_queue.task_done()
        except:
            pass


logger = logging.getLogger()
print('Connecting to graph')
graph = Graph(password='password')  # TODO: parameterize, don't hardcode password


def main():
    sniffer_count = min([cpu_count(), len(argv[1:])])
    sniffer_queue = JoinableQueue()
    db_queue = JoinableQueue()
    for filename in argv[1:]:
        if os.path.isfile(filename):
            print('Will be loading from file', filename)
        else:
            print('Will sniff from interface', filename)
        sniffer_queue.put(filename)
    if argv[1:] == []:
        sniffer_queue.put('*')
        if sniffer_count == 0:
            sniffer_count = 1

    sniffers = []
    for _ in range(sniffer_count):
        p = Process(target=sniffer, args=(sniffer_queue, db_queue))
        p.start()
        sniffers.append(p)
        sniffer_queue.put(None)
    db_proc = Process(target=db_worker, args=(sniffer_count, db_queue))
    db_proc.start()
    interfaces = []
    sniffer_queue.close()
    db_proc.join()
    for _ in sniffers:
        _.join()

if __name__=='__main__':
    main()