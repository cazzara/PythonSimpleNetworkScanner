# Python Simple Network Scanner

Educational project to build a simple port scanner in Python using Scapy.

```
chris@MacBook % python network_scanner.py --help
usage: network_scanner.py [-h] --interface INTERFACE [--num-ports NUM_PORTS]
                          (--target-network TARGETS | --target-hosts TARGETS)

A simple network scanner

optional arguments:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Which network interface to start the scan on. Ex: en0
  --num-ports NUM_PORTS
                        Number of ports to scan (default is 100, max is 1000).
                        Takes top N ports from NMAP list sorted by frequency.
  --target-network TARGETS
                        CIDR notation network to scan ex: 192.168.1.1/24 -
                        Will discover and probe discovered target hosts on the
                        network.
  --target-hosts TARGETS
                        Comma separated value list of hosts ex:
                        192.168.1.1,192.168.1.2,192.168.1.3 - Will discover
                        and probe discovered target hosts on the network.
```

## Usage example
```
chris@MacBook % python network_scanner.py --interface en0 --target-host 192.168.1.1
Local IP Address is 192.168.1.47 - Local MAC Address is 3c:22:fb:e4:db:dd
Scanning targets: 192.168.1.1
Found 192.168.1.1 via ARP at 30:93:bc:5a:94:84
Found 192.168.1.1 via ICMP
Running TCP scan on 192.168.1.1
Found 1 hosts on the network. Scanned top 100 most frequently open ports on each host.
### IP 192.168.1.1 -- MAC_ADDR 30:93:bc:5a:94:84 -- VENDOR ID Sagemcom Broadband SAS ###
Services:
	http - 80/tcp - 0.484143 - # World Wide Web HTTP
	ipp - 631/tcp - 0.006160 - # ipps | Internet Printing Protocol -- for one implementation see http://www.cups.org (Common UNIX Printing System) | IPP (Internet Printing Protocol) | Internet Printing Protocol over HTTPS
Took 2.989185094833374 secs
```
