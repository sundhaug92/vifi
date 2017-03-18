from flask import Flask
import mysql.connector

app = Flask(__name__)

def get_document(ssid=None, mac=None):
    document = ''
    document += '<table><th><b>mac</b></th><th><b>ssid</b></th>\n'
    query='SELECT station_mac, ssid FROM vifi.edges'
    if not ssid is None:
        query += ' WHERE ssid=%(ssid)s'
        if not mac is None:
            query += ' AND station_mac=%(mac)s'
    elif not mac is None:
        query += ' WHERE station_mac=%(mac)s'
    cur.execute(query)
    macs = []
    ssids = []
    edge_count = 0
    for edge in cur.fetchall():
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

config = {
    'user': 'root',
    'password': 'eviltwin',
    'host': '127.0.0.1'
}
cnx = mysql.connector.connect(**config)
cur = cnx.cursor()

if __name__ == "__main__":
    app.run()
