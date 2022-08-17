# Python Simple Network Scanner

Educational project to build a simple port scanner in Python using Scapy.

```
chris@MacBook% python network_scanner.py --help
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
