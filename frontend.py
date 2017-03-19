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
    cur.close()
    cnx.close()
    return return_value

def get_document(ssid=None, mac=None):
    document = ''
    document += '<table><th><b>mac</b></th><th><b>ssid</b></th>\n'
    query='SELECT station_mac, ssid FROM vifi.edges'
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
        document += '<tr><td><a href="/show_mac/{}">{}</a></td><td><a href="/show_ssid/{}">{}</a></td></tr>\n'.format(edge[0], edge[0], edge[1], edge[1])
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

@app.route("/api/nodes.js")
def api_nodes():
    nodes = get_nodes()
    document = 'var nodes = ['
    for node_id in range(len(nodes)):
        is_phone = re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', nodes[node_id]) != None
        document += '{id: %s, label: "%s", shape: "image", image: "%s" },' % (node_id, nodes[node_id].encode('ascii', 'ignore'), 
        {True:'Hardware-My-PDA-02-icon.png', False:'Network-Pipe-icon.png'}[is_phone])
    document = document[:-1] + '];'
    return document

@app.route("/api/edges.js")
def api_edges():
    nodes = get_nodes()
    document = 'var edges = ['
    edges = sql_execute('SELECT station_mac, ssid FROM vifi.edges')
    for (mac, ssid) in edges:
        mac_node_id = str(nodes.index(mac.encode('ascii', 'ignore')))
        ssid_node_id = str(nodes.index(ssid.encode('ascii', 'ignore')))
        document += '{from: %s, to: %s},' % (mac_node_id, ssid_node_id)
    document = document[:-1] + '];'
    return document

@app.route("/static/<path:path>")
def send_static(path):
    flask.send_from_directory(path)

if __name__ == "__main__":
    app.run()
