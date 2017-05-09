#! /usr/bin/python

import sys
from datetime import datetime

from scrapy import conf

try:
    from logging import getLogger, ERROR
    getLogger('scapy.runtime').setLevel(ERROR)
    from scapy.all import *
    conf.verb = 0

except ImportError:
    print("Failed to Import Scapy")
    sys.exit(1)



class ArpEnumerator(object):

    def __init__(self, interface=False, passive=False, range=False):

        self.interface = interface
        self.passive   = passive
        self.range     = range
        self.discovered_hosts = {}
        self.filter = 'arp'
        self.starttime = datetime.now()

"""
Checks if a host has been discovered.
If not, print the IP and MAC.
"""
def passive_handler(self, pkt):

    try:
        if not pkt['ARP'].psrc in self.discovered_hosts.keys():

                print(pkt['ARP'].prsc, pkt['ARP'].hwsrc)

                self.discovered_hosts[pkt['ARP'].prsc] = pkt['ARP'].hwsrc

    except KeyboardInterrupt:

        return


def passive_sniffer(self):

    if not self.range:

        print("Unspecified range; Sniffing all ARP traffic")

    else:

        self.filter += "and (net %s)" %(self.range)

    print("Sniffing started on " + self.interface)

    try:
        sniff(filter=self.filter, prn=self.passive_handler, store=0)

    except Exception:

        print("")

        return


