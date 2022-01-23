import logging

def icmp_trigger(eth, iph, icmph):
    logging.debug("\n".join([
        "ICMP Packet Dump",
        " [>] Dest MAC : " + eth.dest_mac + " Src MAC : " + eth.src_mac  + " Protocol : " + str(eth.protocol),
        " [>] Version : " + str(iph.version) + " TTL : " + str(iph.ttl) + " Protocol : " + str(iph.protocol) + " Src Address : " + iph.src_addr + " Dest Address : " + iph.dest_addr,
        " [>] Type : " + str(icmph.type) + " Code : " + str(icmph.code) + " Checksum : " + str(icmph.checksum),
        " [>] Data : " + str(icmph.data)
    ]))

def tcp_trigger(eth, iph, tcph):
    logging.debug("\n".join([
        "TCP Packet Dump",
        " [>] Dest MAC : " + eth.dest_mac + " Src MAC : " + eth.src_mac  + " Protocol : " + str(eth.protocol),
        " [>] Version : " + str(iph.version) + " TTL : " + str(iph.ttl) + " Protocol : " + str(iph.protocol) + " Src Address : " + iph.src_addr + " Dest Address : " + iph.dest_addr,
        " [>] Src Port : " + str(tcph.src_port) + " Dest Port : " + str(tcph.dest_port) + " Sequence Number : " + str(tcph.sequence) + " Acknowledgement : " + str(tcph.acknowledgement) + " TCP header length : " + str(tcph.length),
        " [>] Data : " + str(tcph.data)
    ]))