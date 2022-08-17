import logging
import netifaces
from socket import socket, AF_INET, SOCK_DGRAM, gethostbyaddr, herror
from multiprocessing import Pool
from ipaddress import IPv4Network
from scapy.all import Ether, ARP, srp1, IP, ICMP, TCP, sr1
from scapy.error import Scapy_Exception
import os
import time
import csv
from collections import defaultdict
import concurrent.futures
from cli import get_parser

logger = logging.getLogger()


class NetworkScanTarget:
    """
    Object used to represent a discovered scan target
    """

    def __init__(self, ip, mac="UNKNOWN", vendor="UNKNOWN"):
        self._ip_addr = ip
        self._mac_addr = mac
        self._mac_addr_vendor = vendor
        # What discovery methods this target responded to, ex: ["ARP", "ICMP"]
        self._discovered_by = []
        self._open_ports = {"tcp": [], "udp": []}

    def __str__(self):
        return f"### IP {self.ip_addr} -- MAC_ADDR {self.mac_addr} -- VENDOR ID {self.vendor} ###"

    @property
    def ip_addr(self):
        return self._ip_addr

    @property
    def mac_addr(self):
        return self._mac_addr

    @property
    def vendor(self):
        return self._mac_addr_vendor

    @vendor.setter
    def vendor(self, v):
        self._mac_addr_vendor = v

    @property
    def discovered_by(self):
        return self._discovered_by

    def add_discovery_method(self, protocol):
        self._discovered_by.append(protocol)

    def add_open_port_info(self, protocol, port_info):
        self._open_ports[protocol].append(port_info)

    def display_target_info(self):
        print(self)
        print("Services:")
        for protocol in self._open_ports:
            for port_info in self._open_ports[protocol]:
                print("\t" + " - ".join(port_info))


class NetworkScan:
    """
    Run a scan against an IPv4 network. Gets the local IP, subnet, and default gateway info
    The different discovery methods are termed "scan phases", ex ARP discovery phase, ICMP discovery phase
    ProcessPoolExecutor multiprocessing module is used to run the scan phases.

    Local
        Discovery Methods - ARP, ICMP?
    Remote 
        Discovery Methods - ICMP, SYN
    """

    NMAP_MAC_ADDR_LIST_FILENAME = "data/nmap-mac-prefixes"
    NMAP_DATA_FILE_LOCATION = "data/nmap-services"

    def __init__(self, interface, targets, num_ports):
        _network_info = self._get_ipv4_interface_info(interface)
        self._mac_addr = _network_info["mac_addr"]
        self._ip_addr = _network_info["addr"]
        self._subnet = _network_info["netmask"]
        self._target_list = targets
        self._local_scan = self._is_local_scan(self.network, self.target_list)
        self._num_ports = num_ports

        # {"192.168.1.1": NetworkScanTarget, ...}
        self._discovered_targets = {}

    def _is_local_scan(self, interface_network, targets):
        return all(target in interface_network for target in targets) 

    @property
    def ip_addr(self):
        """IP Address of host running the scan"""
        return self._ip_addr

    @property
    def mac_addr(self):
        """MAC Address of host running the scan"""
        return self._mac_addr

    @property
    def subnet(self):
        """Local subnet of host running the scan"""
        return self._subnet

    @property
    def network(self):
        """Local IPv4Network of host running the scan"""
        return IPv4Network(f"{self.ip_addr}/{self.subnet}", strict=False)

    @property
    def target_list(self):
        """List of IPv4Address targets of the scan"""
        return self._target_list

    @property
    def local_network_scan(self):
        """Are we scanning the same network as the interface? (will use local discovery/scan methods)"""
        return self._is_local_scan

    @property
    def num_ports(self):
        """Number of ports to probe on each target as part of the network scan"""
        return self._num_ports

    def add_host(self, ip="UNKNOWN", mac="UNKNOWN", vendor="UNKNOWN"):
        old_host = self._discovered_targets.get(ip)
        if old_host is not None:
            ip = ip if old_host.ip_addr == "UNKNOWN" else old_host.ip_addr
            mac = mac if old_host.mac_addr == "UNKNOWN" else old_host.mac_addr
            vendor = vendor if old_host.vendor == "UNKNOWN" else old_host.vendor
            self._discovered_targets[ip] = NetworkScanTarget(ip, mac, vendor)
        else:
            self._discovered_targets[ip] = NetworkScanTarget(ip, mac, vendor)

    def get_host_by_ip(self, ip):
        return self._discovered_targets.get(ip)

    def get_live_hosts(self):
        """Return list of network probe target objects"""
        return [target for target in self._discovered_targets.values()]

    def get_live_host_ips(self):
        """Return list of dsicovered IP addresses"""
        return [ip for ip in self._discovered_targets]

    def _get_ipv4_interface_info(self, interface=None):
        """
        Get information about the interface.
        Returns a dict in the form:

        {
          'addr': '192.168.1.203',
          'netmask': '255.255.255.0',
          'broadcast': '192.168.1.255',
          'gateway': '192.168.1.1'
          'mac_addr': 'de:ad:be:ef:00:00'
        }

        """
        IPV4 = netifaces.AF_INET  # 2
        # IPV6 = netifaces.AF_INET6 # 30
        MAC_ADDR = netifaces.AF_LINK  # 18

        if not interface:
            _, interface = netifaces.gateways()["default"][IPV4]
        iface_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
        iface_hw_addresses = netifaces.ifaddresses(interface)[netifaces.AF_LINK]

        for mac, iface_info in zip(iface_hw_addresses, iface_addresses):
            iface_info.update({"mac_addr": mac["addr"]})
        # TODO: Need to handle many addresses on the interface
        return iface_addresses[0]

    def arp_probe(self, addr):
        """
        For a given IP addr, send a broadcast ARP request on the local network
        Used in local network discovery only.
        Return the response MAC address of the host or None if no response was received
        """
        try:
            result = srp1(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=addr),
                timeout=2,
                verbose=False,
            )
        except Exception as e:
            print(f"Unable to discover {addr} via ARP")
            print(e)
            return None
        if result:
            print(f"Found {addr} via ARP at {result[ARP].hwsrc}")
            return result[ARP].hwsrc

    def icmp_probe(self, addr):
        """
        Send an ICMP echo request to the target address
        Check for an ICMP echo reply to determine if the target is live.
        """
        try:
            result = sr1(IP(dst=addr) / ICMP(), timeout=2, verbose=False,)
        except Exception as e:
            print(f"Unable to discover {addr} via ICMP")
            print(e)
        if result:
            print(f"Found {addr} via ICMP")
            return True
        return False

    def run_arp_discovery(self, hosts):
        with concurrent.futures.ProcessPoolExecutor() as executor:
            for mac_address, host in zip(executor.map(self.arp_probe, hosts), hosts):
                if mac_address:
                    self.add_host(host, mac_address)

    def run_icmp_discovery(self, hosts):
        with concurrent.futures.ProcessPoolExecutor() as executor:
            for is_host_live, host in zip(executor.map(self.icmp_probe, hosts), hosts):
                if is_host_live:
                    self.add_host(host, "UNKNOWN")

    def populate_mac_vendor_info(self):
        """
        For each discovered host, try to find the MAC address vendor
        """
        vendor_info = self.get_mac_addr_vendor_map()
        for host in self.get_live_hosts():
            if host.mac_addr != "UNKNOWN":
                vendor_prefix = "".join(host.mac_addr.split(":")[:3]).upper()
                host.vendor = vendor_info.get(vendor_prefix, "UNKNOWN")

    def discover_hosts(self):
        """
        Discovery phase for the Network Probe
        """
        print(
            f"Local IP Address is {self.ip_addr} - Local MAC Address is {self.mac_addr}"
        )
        print(f"Scanning targets: {' '.join([str(host) for host in self.target_list])}")
        host_ips = [str(host) for host in self.target_list]
        if self.local_network_scan:
            self.run_arp_discovery(host_ips)
            self.populate_mac_vendor_info()
        self.run_icmp_discovery(host_ips)


    def send_tcp_syn_probe(self, port_info):
        """
        For a given port, send a SYN request to each discovered host
        """
        port_num, protocol = port_info[1].split("/")
        results = {}
        for host in self.get_live_host_ips():
            ans = sr1(
                IP(dst=host) / TCP(dport=int(port_num), flags="S"),
                timeout=2,
                verbose=False,
            )
            if ans and self.is_tcp_port_open(ans):
                results[host] = port_info
        return results

    def is_tcp_port_open(self, rsp):
        """
        Given a Scapy packet response, is the port open/closed
        Looks for SA flag (code 18)
        """
        if not rsp:
            return False
        if rsp[TCP].flags.value == 18:  # SYN-ACK
            return True
        return False

    def run_tcp_scan(self):
        """
        Probes top N TCP ports across the discovered hosts
        Starts a process for each port and iterates through each target to probe on that port using `send_tcp_syn_probe`
        """
        print(
            f"Running TCP scan on {', '.join(str(host) for host in self.get_live_host_ips())}"
        )
        ports = self.get_most_common_ports(
            protocol="tcp", num_ports=self.num_ports
        )
        completed_targets = {}
        with concurrent.futures.ProcessPoolExecutor() as executor:
            for port, results in zip(
                ports, executor.map(self.send_tcp_syn_probe, ports)
            ):
                for host_ip, port_info in results.items():
                    self.get_host_by_ip(host_ip).add_open_port_info("tcp", port_info)

    def display_hosts(self):
        print(
            f"Found {len(self.get_live_host_ips())} hosts on the network. Scanned top {self.num_ports} most frequently open ports on each host."
        )
        for host in self.get_live_hosts():
            host.display_target_info()

    @classmethod
    def get_mac_addr_vendor_map(cls):
        """
        Return a map of MAC address prefix to known hardware vendor
        Taken from nmap data - https://nmap.org/book/toc.html
        
        ex:
        {
          '3CBD3E': 'Beijing Xiaomi Electronics',
          '641A22': 'Heliospectra AB',
          'A084CB': 'SonicSensory',
          'D47AE2': 'Samsung Electronics',
          '6854FD': 'Amazon Technologies',
          ...
        }
        """
        mac_addr_vendor_map = {}
        with open(cls.NMAP_MAC_ADDR_LIST_FILENAME) as f:
            data = {
                row.split()[0]: " ".join(row.split()[1:])
                for idx, row in enumerate(f.readlines())
                if idx >= 5
            }
        return data

    @classmethod
    def get_most_common_ports(cls, protocol, num_ports):
        """
        Return a list of the most common (open) ports sorted by frequency. 
        Taken from nmap data - https://nmap.org/book/toc.html
        
        ex:
        [
         ['http', '80/tcp', '0.484143', '# World Wide Web HTTP'],
         ['telnet', '23/tcp', '0.221265'],
         ['https', '443/tcp', '0.208669', '# secure http (SSL)'],
         ['ftp', '21/tcp', '0.197667', '# File Transfer [Control]'],
         ['ssh', '22/tcp', '0.182286', '# Secure Shell Login'],
         ['smtp', '25/tcp', '0.131314', '# Simple Mail Transfer'],
         ...
        ]
        """
        data = []
        with open(cls.NMAP_DATA_FILE_LOCATION) as f:
            csv_f = csv.reader(f, delimiter="\t")
            data = [
                row
                for idx, row in enumerate(csv_f)
                if idx >= 22 and row[1].split("/")[1] == protocol.lower()
            ]
        return sorted(data, key=lambda x: x[2], reverse=True)[:num_ports]


if __name__ == "__main__":
    start = time.time()
    parser = get_parser()
    args = parser.parse_args()
    n = NetworkScan(interface=args.interface, targets=args.targets, num_ports=args.num_ports)
    n.discover_hosts()
    n.run_tcp_scan()
    n.display_hosts()
    end = time.time()
    print(f"Took {end - start} secs")
