# TODO

## PI - Packet Inspector

- Add support for node and relationship data
- Add support for timestamping
- Add support for counting (for example number of packets has a certain relationship)

### Data packets

- Find out who sends what to whom, add ETHER/GEN/MAC_TO_MAC

## DPI - Deep Packet Inspector

- Add support for DNS
- Add support for HTTP
- Add support for SSL

### DHCP

- Use option 61 if available instead of pkt.addr2

## Other

- Neo4j connection: parameterize, don't hardcode password