"""Read-only network planning. No bridge, rules, leases or namespaces are created."""
import ipaddress
import re

_ID = re.compile(r"[0-9a-f]{32}\Z")
_POOL = ipaddress.ip_network("10.240.0.0/16")


def plan(identifier, route_destinations, interfaces, macs, reserved_networks=(), reserved_tables=()):
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ValueError("invalid instance identifier")
    occupied = []
    for value in list(route_destinations) + list(reserved_networks):
        if value == "default":
            continue
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            raise ValueError("expected IPv4 routes only")
        occupied.append(network)
    candidates = list(_POOL.subnets(new_prefix=24))
    offset = int(identifier, 16) % len(candidates)
    subnet = next((candidates[(offset + n) % len(candidates)] for n in range(len(candidates))
                   if not any(candidates[(offset + n) % len(candidates)].overlaps(net) for net in occupied)), None)
    if subnet is None:
        raise ValueError("no collision-free subnet in preview pool")
    bridge = "wmi" + identifier[:11]
    mac = "02:" + ":".join(identifier[i:i + 2] for i in range(0, 10, 2))
    table = "wmi_" + identifier[:12]
    if bridge in set(interfaces):
        raise ValueError("bridge name already in use")
    if mac.lower() in {item.lower() for item in macs}:
        raise ValueError("MAC already in use")
    if table in set(reserved_tables):
        raise ValueError("nftables table already in use")
    return {"bridge": bridge, "mac": mac, "subnet": str(subnet),
            "gateway": str(subnet.network_address + 1),
            "dhcp_start": str(subnet.network_address + 2),
            "dhcp_end": str(subnet.broadcast_address - 1), "nft_table": table,
            "allocated": False, "nft_checked_on_host": False}


def plan_many(identifiers, route_destinations, interfaces, macs, reserved_networks=(), reserved_tables=()):
    """Preview a collision-free batch without reserving or configuring anything."""
    identifiers = list(identifiers)
    if not identifiers or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in identifiers):
        raise ValueError("expected one or more instance identifiers")
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("duplicate instance identifier")
    routes, links, addresses = list(route_destinations), list(interfaces), list(macs)
    networks, tables = list(reserved_networks), list(reserved_tables)
    results = {}
    for identifier in identifiers:
        result = plan(identifier, routes, links, addresses, networks, tables)
        results[identifier] = result
        networks.append(result["subnet"])
        links.append(result["bridge"])
        addresses.append(result["mac"])
        tables.append(result["nft_table"])
    return results
