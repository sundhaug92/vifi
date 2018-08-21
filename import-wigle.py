import sqlite3, requests, os
from py2neo.database import Graph, Node, Relationship
from sys import argv


def get_human_address_display_string(road, housenumber, city, region, country):
    s = '{} {}, {}, {}, {}'.format(road, housenumber, city, region, country)
    while '  ' in s:
        s = s.replace('  ', ' ')
    while ' ,' in s:
        s = s.replace(' ,', ',').replace('  ', ' ')
    while ', ,' in s:
        s = s.replace(', ,', ', ').replace('  ', ' ')
    return s


def register_connection(connection, from_node_name, to_node_name):
    from_node, to_node = None, None
    if connection in ['WIFI/MGMT/BEACON']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('network', essid=to_node_name)
    elif connection in ['WIFI/WIGLE/BSSID/POS/BEST', 'WIFI/WIGLE/BSSID/POS/LAST', 'WIFI/WIGLE/BSSID/POS/ONLINE']:
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('pos2d', lat=to_node_name[0], lon=to_node_name[1])
    elif connection in ['WIFI/WIGLE/SSID/POS/BEST', 'WIFI/WIGLE/SSID/POS/LAST', 'WIFI/WIGLE/SSID/POS/ONLINE']:
        from_node = Node('network', essid=from_node_name)
        to_node = Node('pos2d', lat=to_node_name[0], lon=to_node_name[1], display_string=','.join([str(_) for _ in to_node_name]))
    elif connection in ['WIFI/WIGLE/BSSID/SIGNAL_STRENGTH']:
        (lat, lon, altitude, level, accuracy) = to_node_name
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('signal_measurement', lat=lat, lon=lon, altitude=altitude, level=level, accuracy=accuracy)
    elif connection in ['WIFI/WIGLE/SSID/SIGNAL_STRENGTH']:
        (lat, lon, altitude, level, accuracy) = to_node_name
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('signal_measurement', lat=lat, lon=lon, altitude=altitude, level=level, accuracy=accuracy)
    elif connection in ['WIFI/WIGLE/BSSID/POS/HUMAN']:
        (road, housenumber, city, region, country) = to_node_name
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('human_address', road=road, housenumber=housenumber, city=city, region=region, country=country, display_string=get_human_address_display_string(road, housenumber, city, region, country))
    elif connection in ['WIFI/WIGLE/SSID/POS/HUMAN']:
        (road, housenumber, city, region, country) = to_node_name
        from_node = Node('device', mac_address=from_node_name)
        to_node = Node('human_address', road=road, housenumber=housenumber, city=city, region=region, country=country, display_string=get_human_address_display_string(road, housenumber, city, region, country))
    if None in [from_node, to_node]:
        raise Exception('Unknown connection type', connection)
    rel = Relationship(from_node, connection, to_node)
    graph.merge(rel)


def handle_db(filename):
    print('Loading', filename)
    conn = sqlite3.connect(filename)
    c = conn.cursor()
    print(' * Loading location')
    for (_id, bssid, level, lat, lon, altitude, accuracy, time) in c.execute('SELECT * FROM location WHERE bssid LIKE "%:%" AND time!=0'):
        print(_id, bssid, level, lat, lon, altitude, accuracy, time)
        register_connection('WIFI/WIGLE/BSSID/SIGNAL_STRENGTH', bssid, (lat, lon, altitude, level, accuracy))
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


def get_wigle_network_search_data(ap_mac, essid):
    return requests.get('https://api.wigle.net/api/v2/network/search?netid={}&ssid={}'.format(ap_mac, essid), headers={'Authorization': 'Basic ' + os.environ['WIGLE_AUTH']}).json()


def get_wigle_network_detail_data(ap_mac):
    return requests.get('https://api.wigle.net/api/v2/network/detail?netid={}'.format(ap_mac), headers={'Authorization': 'Basic ' + os.environ['WIGLE_AUTH']}).json()


def handle_online():
    print('Loading online')
    if 'WIGLE_AUTH' not in os.environ:
        raise Exception('WIGLE_AUTH not set')
    load_network_search_data = True
    load_network_detail_data = True

    def _get_network_search_data(ap_mac, essid):
        j = get_wigle_network_search_data(ap_mac, essid)
        if not j['success']:
            print(j['message'])
            return False
        register_connection('WIFI/MGMT/BEACON', ap_mac, essid)
        for result in j['results']:
            trilat, trilong, housenumber, road, city, region, country = result['trilat'], result['trilong'], result['housenumber'], result['road'], result['city'], result['region'], result['country']
            register_connection('WIFI/WIGLE/BSSID/POS/ONLINE', ap_mac, (trilat, trilong))
            register_connection('WIFI/WIGLE/SSID/POS/ONLINE', essid, (trilat, trilong))
            register_connection('WIFI/WIGLE/BSSID/POS/HUMAN', ap_mac, (road, housenumber, city, region, country))
            register_connection('WIFI/WIGLE/SSID/POS/HUMAN', essid, (road, housenumber, city, region, country))
        return True

    def _get_network_detail_data(ap_mac):
        j = get_wigle_network_detail_data(ap_mac)
        if not j['success']:
            print(j['message'])
            return False
        for result in j['results']:
            trilat, trilong, ssid, housenumber, road, city, region, country = result['trilat'], result['trilong'], result['ssid'], result['housenumber'], result['road'], result['city'], result['region'], result['country']
            register_connection('WIFI/MGMT/BEACON', ap_mac, ssid)
            register_connection('WIFI/WIGLE/BSSID/POS/ONLINE', ap_mac, (trilat, trilong))
            register_connection('WIFI/WIGLE/SSID/POS/ONLINE', ssid, (trilat, trilong))
            if not any([_ is None for _ in (housenumber, road, city, region, country)]):
                register_connection('WIFI/WIGLE/BSSID/POS/HUMAN', ap_mac, (road, housenumber, city, region, country))
                register_connection('WIFI/WIGLE/SSID/POS/HUMAN', ssid, (road, housenumber, city, region, country))
            for measurement in result['locationData']:
                register_connection('WIFI/WIGLE/BSSID/SIGNAL_STRENGTH', ap_mac, (measurement['latitude'], measurement['longitude'], measurement['alt'], measurement['signal'], measurement['accuracy']))
                register_connection('WIFI/WIGLE/SSID/SIGNAL_STRENGTH', ssid, (measurement['latitude'], measurement['longitude'], measurement['alt'], measurement['signal'], measurement['accuracy']))

        return True

    pairs_done = []
    for _ in graph.run(
        'MATCH p=(d:device)-[:`WIFI/MGMT/BEACON`|:`WIFI/MGMT/PROBE_RESPONSE/MAC_SENT_SSID`]-(n:network)'
        'WHERE NOT (d)-[:`WIFI/WIGLE/BSSID/POS/ONLINE`]-()'
        'RETURN p'):
        rel = _['p']
        ap_mac, essid = rel.start_node()['mac_address'], rel.end_node()['essid']
        print(ap_mac, essid)
        if (ap_mac, essid) in pairs_done:
            continue
        pairs_done.append((ap_mac, essid))
        if load_network_search_data and not _get_network_search_data(ap_mac, essid):
            load_network_search_data = False
        if load_network_detail_data and not _get_network_detail_data(ap_mac):
            load_network_detail_data = False
        if (not load_network_search_data) and (not load_network_detail_data):
            raise Exception('Something went dead')



graph = Graph(password='password')  # TODO: parameterize, don't hardcode password

for _ in argv[1:]:
    handle_db(_)

handle_online()