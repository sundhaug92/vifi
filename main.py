from scapy.all import *
from xml.sax.saxutils import escape
import mysql.connector

def register_edge(station_mac, ssid):
    print(station_mac, ssid)
    cur.execute('SELECT 1 FROM vifi.edges WHERE station_mac=%s AND ssid=%s', (station_mac, ssid))
    r = cur.fetchall()
    if r == []:
        cur.execute('INSERT INTO vifi.edges VALUES(%s,%s,%s,%s)', (time.time(),time.time(),station_mac, ssid))
    else:
        cur.execute('UPDATE vifi.edges SET last_seen=%s WHERE station_mac=%s AND ssid=%s', (time.time(),station_mac,ssid))
    cnx.commit()

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        try:
            if pkt.type == 0 and pkt.subtype == 4 and pkt.info != '':
                probed_ssid = escape(pkt.info)
                probing_mac = escape(pkt.addr2)
                if probed_ssid != pkt.info:
                    return #Hack
                register_edge(probing_mac, probed_ssid)
        except AttributeError:
            pass

cnx, cur = None, None
def main():
    config = {
        'user': 'root',
        'password': 'eviltwin',
        'host': '127.0.0.1'
    }
    cnx = mysql.connector.connect(**config)
    cur = cnx.cursor()

    cur.execute('CREATE DATABASE IF NOT EXISTS vifi;')
    cur.execute('CREATE TABLE IF NOT EXISTS vifi.edges(first_seen DOUBLE, last_seen DOUBLE, station_mac TEXT, ssid TEXT);')
    cnx.commit()

    sniff(iface="rename7", store=0, prn = PacketHandler)

if __name__ == '__main__':
    main()
