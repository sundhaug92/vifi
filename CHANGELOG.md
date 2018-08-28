# Changelog

2018-08-05 - Switched to rewrite tentatively called "vifi2" with [d126c85](https://https://github.com/sundhaug92/vifi/commit/d126c85a562b915219e59926886e689c0468325d), old code should be in [v1.0 branch](https://github.com/sundhaug92/vifi/tree/v1.0).

## Unreleased

### Added

- Added support for ARP, BOOTP, DHCP, EAP, IP, TCP, UDP

### Changed

- Switched the backend to be based on neo4j, replacing MySQL. This should drastically improve performance.
- Renamed relationship types to make the names more specific
  - "PROBE_REQUEST" is now "WIFI/MGMT/PROBE_REQUEST"
  - "PROBE_RESPONSE_TO" is now "WIFI/MGMT/PROBE_RESPONSE/MAC_RECV_SSID"
  - "PROBE_RESPONSE_FROM" is now "WIFI/MGMT/PROBE_RESPONSE/MAC_SENT_SSID"
  - "BEACON" is now "WIFI/MGMT/BEACON"

### Removed

#### Might return

- Removed the OUI-identification system, may return at a later point
- "PROBE_RESPONSE_DATA", can be inferred from "WIFI/MGMT/PROBE_REQUEST", "WIFI/MGMT/PROBE_RESPONSE/MAC_RECV_SSID", "WIFI/MGMT/PROBE_RESPONSE/MAC_SENT_SSID" and "ETHER/GEN/MAC_TO_MAC"
- Generic management frames are not currently logged, will probably be replaced with specific relationship types
- Data frames are currently not generally logged

#### Permanently

- Removed the old UI, use the neo4j UI (port 7474 by default), should make things much more stable and performant