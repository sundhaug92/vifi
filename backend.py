from scapy.all import *
from xml.sax.saxutils import escape
import mysql.connector
import time
from macpy import Mac

def register_edge(assoc_type, station_mac, ssid):
    global cnx, cur
    if escape(ssid) != ssid or '\x00' in ssid or len(ssid) > 32:
        return
    if any([ord(c) not in range(128) for c in ssid]):
        return
    config = {
        'user': 'root',
        'password': 'eviltwin',
        'host': '127.0.0.1'
    }
    cnx = mysql.connector.connect(**config)
    cur = cnx.cursor()
    cur.execute('SELECT 1 FROM vifi.edges WHERE station_mac=%s AND ssid=%s AND assoc_type=%s', (station_mac, ssid, assoc_type))
    r = cur.fetchall()
    if r == []:
        cur.execute('INSERT INTO vifi.edges VALUES(%s,%s,%s, %s,%s)', (time.time(),time.time(),assoc_type,station_mac, ssid))
    else:
        cur.execute('UPDATE vifi.edges SET last_seen=%s WHERE station_mac=%s AND ssid=%s AND assoc_type=%s', (time.time(),station_mac,ssid,assoc_type))


    cur.execute('DELETE FROM vifi.edges WHERE last_seen<{} AND (station_mac LIKE "_2%" OR station_mac LIKE "_6%" OR station_mac LIKE "_A%" OR station_mac LIKE "_E%")'.format(time.time() - 300)) #Remove private MACs not seen in 5m
#    cur.execute('DELETE FROM vifi.edges WHERE last_seen<{}'.format(time.time() - (8 * 3600))) # Delete public MACs not seen in 8h
    cnx.commit()
    cnx.close()

def register_mac_meta(station_mac):
    if station_mac[1] in ['2', '6', 'a', 'A', 'e', 'E']:
        return
    config = {
        'user': 'root',
        'password': 'eviltwin',
        'host': '127.0.0.1'
    }
    cnx = mysql.connector.connect(**config)
    cur = cnx.cursor()
    cur.execute('SELECT 1 FROM vifi.mac_meta WHERE station_mac="{}"'.format(station_mac))
    result = cur.fetchall()
    if result != []:
        cur.close()
        cnx.close()
        return
    manufacturer = Mac().search(station_mac.upper())
    if not (manufacturer is None or manufacturer['com'] == ''):
        cur.execute('INSERT INTO vifi.mac_meta VALUES("{}","{}")'.format(station_mac, manufacturer['com']))
        cnx.commit()
        cnx.close()

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        try:
            #print(pkt.type, pkt.subtype, pkt.addr1, pkt.addr2, pkt.addr3, pkt.info)
            if pkt.type == 0 and pkt.info != '':
                if pkt.subtype == 4: # PROBE REQUEST
                    print('PROBE REQUEST: ' + ', '.join([pkt.addr1, pkt.addr2, pkt.addr3, pkt.info]))
                    probed_ssid = escape(pkt.info)
                    probing_mac = escape(pkt.addr2)
                    register_edge('PROBE_REQUEST', probing_mac, probed_ssid)
                    register_mac_meta(probing_mac)
                elif pkt.subtype == 5: # PROBE RESPONSE
                    print('PROBE RESPONSE: ' + ', '.join([pkt.addr1, pkt.addr2, pkt.addr3, pkt.info]))
                    ssid = escape(pkt.info)
                    to_mac = escape(pkt.addr1)
                    from_mac = escape(pkt.addr2)
                    register_edge('PROBE_RESPONSE_TO', to_mac, ssid)
                    register_edge('PROBE_RESPONSE_FROM', from_mac, ssid)
                    register_mac_meta(to_mac)
                    register_mac_meta(from_mac)
                elif pkt.subtype == 8 and pkt.info != '': # BEACON
#                    print('BEACON: ' + ', '.join([pkt.addr1, pkt.addr2, pkt.addr3, pkt.info]))
                    beaconing_ssid = escape(pkt.info)
                    beaconing_mac = escape(pkt.addr2)
                    register_edge('BEACON', beaconing_mac, beaconing_ssid)
                    register_mac_meta(beaconing_mac)
                else:
                    print('MGMT(0,{}): '.format(pkt.subtype) + ', '.join([pkt.addr1, pkt.addr2, pkt.addr3]))
                    register_edge('MGMT-{}'.pkt.subtype, escape(pkt.info), pkt.addr2)
                    register_edge('MGMT-{}'.pkt.subtype, escape(pkt.info), pkt.addr3)
                    register_mac_meta(pkt.addr2)
                    register_mac_meta(pkt.addr3)
            elif pkt.type == 1:
#                print('CTRL(1,{}): '.format(pkt.subtype) + ', '.join([pkt.addr1, pkt.addr2, pkt.addr3]))
                pass
            elif pkt.type == 2:
                print('DATA(2,{}): '.format(pkt.subtype) + ', '.join([pkt.addr1, pkt.addr2, pkt.addr3]))
                pass
        except AttributeError:
            pass

cnx, cur = None, None
def main():
    global cnx, cur
    config = {
        'user': 'root',
        'password': 'eviltwin',
        'host': '127.0.0.1'
    }
    cnx = mysql.connector.connect(**config)
    cur = cnx.cursor()

#    cur.execute('DROP DATABASE vifi;')
    cur.execute('CREATE DATABASE IF NOT EXISTS vifi;')
    cur.execute('CREATE TABLE IF NOT EXISTS vifi.edges(first_seen DOUBLE, last_seen DOUBLE, assoc_type TEXT, station_mac TEXT, ssid TEXT);')
    cur.execute('CREATE TABLE IF NOT EXISTS vifi.mac_meta(station_mac TEXT, manufacturer TEXT);')
    cnx.commit()
    cnx.close()
    sniff(iface="rename7", store=0, prn = PacketHandler)

if __name__ == '__main__':
    main()
