from lxml import etree
import sys
from py2neo.database import Graph, Node, Relationship


def register_connection(connection_type, from_node_name, to_node_name):
    from_node, to_node = None, None
    if connection_type in ['IP/RESOLVED_HOSTNAME']:
        from_node = Node('ip', ip_address=from_node_name)
        to_node = Node('hostname', hostname=to_node_name)
    elif connection_type in ['IP/PORT']:
        from_node = Node('ip', ip_address=from_node_name)
        to_node = Node('ip_port', port_name=from_node_name + ':{}/{}'.format(to_node_name[1], to_node_name[0]))
    elif connection_type in ['IP/ROUTES']:
        from_node = Node('ip', ip_address=from_node_name)
        to_node = Node('ip', ip_address=to_node_name)
    else:
        raise Exception('Unknown connection type {}'.format(connection_type))
    rel = Relationship(from_node, connection_type, to_node)
    graph.merge(rel)


def ip_to_str(ip):
    if ':' in ip:
        return '[' + ip + ']'
    return ip


graph = Graph(password='password')  # TODO: parameterize, don't hardcode password

for filename in sys.argv[1:]:
    tree = etree.XML(open(filename, 'rb').read())
    for host in tree.xpath('//host'):
        for address in host.xpath('./address'):
            addr = ip_to_str(address.get('addr'))
            for hostname in host.xpath('./hostnames/hostname'):
                hostname_name = hostname.get('name')
                register_connection('IP/RESOLVED_HOSTNAME', addr, hostname_name)
            for port in host.xpath('./ports/port'):
                if len(port.xpath('./state[@state="open"]')) == 0:
                    continue
                protocol, portid = port.get('protocol'), port.get('portid')
                register_connection('IP/PORT', addr, (protocol, portid))
            prev_hop = None
            for hop in host.xpath('./trace/hop'):
                register_connection('IP/RESOLVED_HOSTNAME', ip_to_str(hop.get('ipaddr')), hop.get('host'))
                if prev_hop is not None:
                    register_connection('IP/ROUTES', prev_hop, ip_to_str(hop.get('ipaddr')))
                prev_hop = ip_to_str(hop.get('ipaddr'))