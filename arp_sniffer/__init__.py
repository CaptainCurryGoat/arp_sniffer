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

        