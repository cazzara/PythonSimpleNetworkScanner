import argparse
from ipaddress import IPv4Network, IPv4Address

def get_parser():
    parser = argparse.ArgumentParser(description="A simple network scanner")
    parser.add_argument(
        "--interface",
        help="Which network interface to start the scan on. Ex: en0",
        required=True,
    )
    parser.add_argument("--num-ports", help="Number of ports to scan (default is 100, max is 1000). Takes top N ports from NMAP list sorted by frequency.", default=100, type=port_number)
    network_group = parser.add_mutually_exclusive_group(required=True)
    network_group.add_argument(
        "--target-network",
        help="CIDR notation network to scan ex: 192.168.1.1/24 - Will discover and probe discovered target hosts on the network.",
        type=convert_network_to_hosts,
        dest="targets"
    )
    network_group.add_argument(
        "--target-hosts",
        help="Comma separated value list of hosts ex: 192.168.1.1,192.168.1.2,192.168.1.3 - "
        "Will discover and probe discovered target hosts on the network.",
        type=convert_to_host_list,
        dest="targets"
    )
    return parser


def convert_network_to_hosts(network_arg):
    """
    All IPv4Address hosts in the network CIDR range
    """
    try:
        return [host for host in IPv4Network(network_arg, strict=False).hosts()]
    except Exception:
        raise argparse.ArgumentTypeError(f"Cannot convert {network_arg} to IPv4Network")

def convert_to_host_list(hosts_arg):
    """
    All IPv4Address hosts in the comma separated list
    """
    failed_hosts = []
    hosts_list = []
    hosts_arg = hosts_arg.split(",")
    for host in hosts_arg:
        try:
            hosts_list.append(IPv4Address(host))
        except Exception:
            failed_hosts.append(host)
    if failed_hosts:
        raise argparse.ArgumentTypeError(f"Could not convert all hosts to IPv4Address: {' '.join([host for host in failed_hosts])}")
    return hosts_list

def port_number(port_arg):
    """
    Check number of ports is between 1 - 1000
    """
    try:
        if 1 <= int(port_arg) <= 1000:
            return int(port_arg)
        raise argparse.ArgumentTypeError(f"Port Number must be between 1 and 1000: {port_arg}")
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Cannot convert {port_arg} to port number")
