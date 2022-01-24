import logging
import nmap
import cachetools.func

@cachetools.func.ttl_cache(maxsize=256, ttl=60*60)
def scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-T5 -A --top-ports 500")
    return "\t" + nm.csv().replace("\n", "\n\t")

def icmp_trigger(eth, iph, icmph):
    logging.debug("\n".join([
        "ScanBack output for ICMP",
        scan(iph.src_addr)
    ]))

def tcp_trigger(eth, iph, tcph):
    logging.debug("\n".join([
        "ScanBack output for TCP",
        scan(iph.src_addr)
    ]))