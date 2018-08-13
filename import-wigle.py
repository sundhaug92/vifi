import sqlite3
from py2neo.database import Graph, Node, Relationship
from sys import argv

def register_connection(connection, from_node_name, to_node_name):
    from_node, to_node = None, None
    if connection in ['WIFI/MGMT/BEACON']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('network', essid=to_node_name)
    elif connection in ['WIFI/WIGLE/BSSID/POS/BEST', 'WIFI/WIGLE/BSSID/POS/LAST']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('pos2d', lat=to_node_name[0], lon=to_node_name[1])
    elif connection in ['WIFI/WIGLE/SSID/POS/BEST', 'WIFI/WIGLE/SSID/POS/LAST']:
        from_node = Node('network', essid=from_node_name)
        to_node = Node('pos2d', lat=to_node_name[0], lon=to_node_name[1])

    if None in [from_node, to_node]:
        raise Exception('Unknown connection type', connection)
    rel = Relationship(from_node, connection, to_node)
    graph.merge(rel)

def handle_db(filename):
    print('Loading', filename)
    conn = sqlite3.connect(filename)
    c = conn.cursor()
    # print(' * Loading location')
    # for (_id, bssid, level, lat, lon, altitude, accuracy, time) in c.execute('SELECT * FROM location WHERE bssid LIKE "%:%"'):
    #     print(_id, bssid, level, lat, lon, altitude, accuracy, time)
    print(' * Loading network')
    for (bssid, ssid, frequency, capabilities, lasttime, lastlat, lastlon, _type, bestlevel, bestlat, bestlon) in c.execute('SELECT * FROM network WHERE type="W"'):
        print(bssid, ssid, frequency, capabilities, lasttime, lastlat, lastlon, _type, bestlevel, bestlat, bestlon)
        if ssid != '':
            register_connection('WIFI/MGMT/BEACON', bssid, ssid)
            register_connection('WIFI/WIGLE/SSID/POS/BEST', ssid, (bestlat, bestlon))
            register_connection('WIFI/WIGLE/SSID/POS/LAST', ssid, (lastlat, lastlon))
        register_connection('WIFI/WIGLE/BSSID/POS/BEST', bssid, (bestlat, bestlon))
        register_connection('WIFI/WIGLE/BSSID/POS/LAST', bssid, (lastlat, lastlon))
    conn.close()

graph = Graph(password='password')  # TODO: parameterize, don't hardcode password

for _ in argv[1:]:
    handle_db(_)