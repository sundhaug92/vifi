import datetime
from flask import Flask
import mysql.connector
import re

app = Flask(__name__)

def sql_execute(query):
    config = {
        'user': 'root',
        'password': 'eviltwin',
        'host': '127.0.0.1'
    }
    cnx = mysql.connector.connect(**config)
    cur = cnx.cursor()

    cur.execute(query)
    return_value = cur.fetchall()
    cnx.commit()
    cur.close()
    cnx.close()
    return return_value

def get_document(ssid=None, mac=None):
    document = ''
    document += '<table><th><b>first_seen</b></th><th><b>last_seen</b></th><th><b>mac</b></th><th><b>ssid</b></th><th><b>assoc_type</b></th>\n'
    query='SELECT station_mac, ssid, assoc_type, first_seen, last_seen FROM vifi.edges'
    if not ssid is None:
        query += ' WHERE ssid="{}"'.format(ssid)
        if not mac is None:
            query += ' AND station_mac="{}"'.format(mac)
    elif not mac is None:
        query += ' WHERE station_mac="{}"'.format(mac)
    macs = []
    ssids = []
    edge_count = 0
    for edge in sql_execute(query):
        document += '<tr><td>{}</td><td>{}</td><td><a href="/show_mac/{}">{}</a></td><td><a href="/show_ssid/{}">{}</a></td><td>{}</td></tr>\n'.format(get_timestamp_string(edge[3]), get_timestamp_string(edge[4]), edge[0], edge[0], edge[1], edge[1], edge[2])
        macs.append(edge[0])
        ssids.append(edge[1])
        edge_count += 1
    document += '</table>\n\n'
    document += '<table><th><b>Edges</b></th><th><b>Unique MACs</b></td><th><b>Unique SSIDs</b></th>'
    document += '<tr><td>{}</td><td>{}<td>{}</td></tr></table>\n\n'.format(edge_count, len(set(macs)), len(set(ssids)))
    return document

@app.route("/")
def show_all():
    return get_document()

@app.route("/show_mac/<mac>")
def show_mac(mac):
    return get_document(mac=mac)

@app.route("/show_ssid/<ssid>")
def show_ssid(ssid):
    return get_document(ssid=ssid)

def get_nodes():
    nodes = sql_execute('SELECT DISTINCT station_mac FROM vifi.edges') + \
            sql_execute('SELECT DISTINCT ssid FROM vifi.edges')
    nodes = list(set(nodes))
    return [n[0].encode('ascii', 'ignore') for n in nodes]

def get_mac_metadata(mac_addr):
    meta = sql_execute('SELECT manufacturer FROM vifi.mac_meta WHERE station_mac="{}"'.format(mac_addr))
    if meta == [] or meta is None:
        return ''
    return 'Manufacturer: ' + meta[0][0] + '<br/>'

def get_timestamp_string(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def get_node_type(node_name):
    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', node_name) == None:
        return 'SSID'
    assoc_types = [_[0].decode('ascii', 'ignore') for _ in sql_execute('SELECT DISTINCT assoc_type FROM vifi.edges WHERE station_mac="{}"'.format(node_name))]
    manufacturer = sql_execute('SELECT manufacturer FROM vifi.mac_meta WHERE station_mac="{}"'.format(node_name))
    if manufacturer != []:
        manufacturer = manufacturer[0][0].encode('ascii')
    else:
        manufacturer = ''
    ap_like = any([_ in ['BEACON', 'PROBE_RESPONSE_FROM'] for _ in assoc_types])
    client_like = any([_ in ['PROBE_RESPONSE_TO', 'PROBE_REQUEST'] for _ in assoc_types])
    if ap_like and client_like:
        return 'AP/client'
    elif ap_like:
        return 'AP'
    elif client_like:
        if manufacturer == 'Apple, Inc.':
            return 'Apple client device'
        if manufacturer == 'Google Inc':
            return 'Google client device'
        if manufacturer == 'Intel Corporate':
            return 'Intel client device'
        if manufacturer.startswith('Samsung '):
            return 'Samsung client device'
        return 'Client'
    else:
        return 'Unknown'

def get_node_metadata(node_name):
    document_fragment = ''
    timestamps = list(sql_execute('SELECT first_seen,last_seen FROM vifi.edges WHERE station_mac="{}" OR ssid="{}"'.format(node_name, node_name)))
    if not re.match(r'([0-9a-f]{2}\:?){6}', node_name) is None and sql_execute('SELECT 1 FROM vifi.edges WHERE station_mac="{}"'.format(node_name)) != []: #MAC
        document_fragment += '<b>{}</b><br/>'.format(get_node_type(node_name))
        document_fragment += get_mac_metadata(node_name) + '<br/>'
        document_fragment += '<b>First seen: </b>' + get_timestamp_string(timestamps[0][0]) +'<br/>'
        document_fragment += '<b>Last seen: </b>' + get_timestamp_string(timestamps[-1][1]) +'<br/>'
        document_fragment += '<b>Related SSIDs</b><br/>'
        document_fragment += '<br/>'.join(sorted(set([_[0] for _ in sql_execute('SELECT ssid FROM vifi.edges WHERE station_mac="{}"'.format(node_name))])))
    else: # SSID
        document_fragment += '<b>SSID</b><br/>'
        document_fragment += '<b>First seen: </b>' + get_timestamp_string(timestamps[0][0]) +'<br/>'
        document_fragment += '<b>Last seen: </b>' +get_timestamp_string(timestamps[-1][1]) +'<br/>'
        document_fragment += '<b>Related devices</b><br/>'
        document_fragment += '<br/>'.join(sorted(set([_[0] for _ in sql_execute('SELECT station_mac FROM vifi.edges WHERE ssid="{}"'.format(node_name))])))
    return document_fragment
    

@app.route("/api/nodes.js")
def api_nodes():
    nodes = get_nodes()
    document = 'var nodes = ['
    for node_id in range(len(nodes)):
        image_dict = {'Unknown':'Hardware-My-PDA-02-icon.png', 'AP':'ap.png', 'Client':'Hardware-My-PDA-02-icon.png','AP/client':'Hardware-My-PDA-02-icon.png','SSID':'Network-Pipe-icon.png', 
                      'Apple client device':'apple.jpg', 'Google client device': 'google.png', 'Intel client device': 'intel.ico', 'Samsung client device': 'samsung.jpg'}
        image_url = image_dict[get_node_type(nodes[node_id])]
        document += '{id: %s, label: "%s", shape: "image", image: "%s", title: "%s" },' % (node_id, nodes[node_id].encode('ascii', 'ignore'),
        image_url, get_node_metadata(nodes[node_id]))
    document = document[:-1] + '];'
    return document

@app.route("/api/edges.js")
def api_edges():
    nodes = get_nodes()
    document = 'var edges = ['
    edges = sql_execute('SELECT first_seen, last_seen, station_mac, ssid, assoc_type FROM vifi.edges')
    for (first_seen, last_seen, mac, ssid, assoc_type) in edges:
        mac_node_id = str(nodes.index(mac.encode('ascii', 'ignore')))
        ssid_node_id = str(nodes.index(ssid.encode('ascii', 'ignore')))
        if assoc_type == 'PROBE_RESPONSE_TO':
            document += '{from: %s, to: %s, title: "%s: %s->%s<br/>First seen: %s<br/>Last seen: %s"},' % (mac_node_id, ssid_node_id, assoc_type, ssid.encode('ascii', 'ignore'), mac,  get_timestamp_string(first_seen),  get_timestamp_string(last_seen))
        else:
            document += '{from: %s, to: %s, title: "%s: %s->%s<br/>First seen: %s<br/>Last seen: %s"},' % (mac_node_id, ssid_node_id, assoc_type, mac, ssid.encode('ascii', 'ignore'),  get_timestamp_string(first_seen),  get_timestamp_string(last_seen))
    document = document[:-1] + '];'
    return document

@app.route("/static/<path:path>")
def send_static(path):
    flask.send_from_directory(path)

if __name__ == "__main__":
    app.run()
