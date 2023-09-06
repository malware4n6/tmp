#!/usr/bin/env python3
import argparse
import logging
import sys
from scapy.all import *
from datetime import datetime

__author__ = "malware4n6"
__copyright__ = "malware4n6"
__license__ = "The Unlicense"
__version__ = "0.0.1"

log = logging.getLogger(__name__)
pp = None
def analyze_pcap(pcap_path):
    pcap = rdpcap(pcap_path)
    pkts = [p for p in pcap]
    for pkt in pkts:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            pkt[IP].show()#print(pkt[TCP])
#            pkt.show()
            
            # raw = pkt.getlayer(Raw)
            # dt = datetime.fromtimestamp(float(pkt.time))
            # str_dt = dt.strftime('%Y-%m-%d %H:%M:%S')
            # print(str_dt, len(raw))
            # raw.show()


def parse_args(args):
    parser = argparse.ArgumentParser(description="Scapy test")
    parser.add_argument("--version", action="version", version="rh2yara {ver}".format(ver=__version__))
    parser.add_argument("-i", "--input", help="path to some pcap (use -i for each input file)",
                        type=str, required=True, action='append')
    parser.add_argument("-o", "--output",
                        help="path to generated Yara",
                        type=str, default=None)
    parser.add_argument("-v", "--verbose", dest="verbose", help="set loglevel to DEBUG",
                        action='store_true')
    return parser.parse_args(args)

def setup_logging(verbose=False):
    """
    if verbose, logging.loglevel is set to DEBUG instead of INFO
    warning: logging output is done on stderr
    """
    logformat = "[%(asctime)s] %(levelname)s\t%(name)s\t%(message)s"
    loglevel = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=loglevel, stream=sys.stderr, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )


def main(args):
    args = parse_args(args)
    setup_logging(args.verbose)
    for pcap in args.input:
        pkt = analyze_pcap(pcap)
    return pkt

if __name__ == "__main__":
    main(sys.argv[1:])
