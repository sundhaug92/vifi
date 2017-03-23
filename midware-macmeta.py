from macpy import Mac
import mysql.connector
import sys
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
    if manufacturer is None or manufacturer['com'] == '':
        manufacturer = {'com': 'Unknown'}
    cur.execute('INSERT INTO vifi.mac_meta VALUES("{}","{}")'.format(station_mac, manufacturer['com']))
    cnx.commit()
    cnx.close()

for _ in sys.argv[1:]: register_mac_meta(_)
