from py2neo.database import Graph, Node, Relationship
from manuf import manuf
import multiprocessing

def register_connection(connection, from_node_name, to_node_name):
    from_node, to_node = None, None
    if connection in ['ETHER/GEN/OUI/MANUFACTURED_BY']:
        from_node = Node('device', mac_address=from_node_name)
        if len(to_node_name) == 1:
            to_node = Node('manufacturer', manuf_name=to_node_name[0])
        else:
            to_node = Node('manufacturer', manuf_name=to_node_name[0], manuf_comment=to_node_name[1])
    if None in [from_node, to_node]:
        raise Exception('Unknown connection type', connection)
    rel = Relationship(from_node, connection, to_node)
    graph.merge(rel)


def worker(mac_address):
    print(mac_address)
    manuf_data = mac_parser.get_all(mac_address)
    if manuf_data is None or manuf_data.manuf is None:
        return
    register_connection('ETHER/GEN/OUI/MANUFACTURED_BY', mac_address, (manuf_data.manuf,manuf_data.comment))
graph = Graph(password='password')  # TODO: parameterize, don't hardcode password
mac_parser = manuf.MacParser(update=True)
if __name__ == '__main__':
    pool = multiprocessing.Pool(multiprocessing.cpu_count())
    manuf.MacParser(update=True)
    macs = [_['d.mac_address'] for _ in graph.run('MATCH (d:device) WHERE NOT (d)-[:`ETHER/GEN/OUI/MANUFACTURED_BY`]-() RETURN d.mac_address')]
    pool.map(worker, macs)
