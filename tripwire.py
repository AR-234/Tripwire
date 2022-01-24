import socket, sys, struct, ipaddress, importlib, os, logging
import ratelimit


class Tripwire:
    ratelimitCalls = 5
    ratelimitPeriod = 10

    def __init__(self):
        self.triggers = {}
        self.package = 'trigger'
        modList = self.getTriggerModules()
        for mod in modList:
            self.loadTrigger(mod)

    def loadTrigger(self, module):
        logging.info("Loaded trigger: %s" % module)
        self.triggers[module] = importlib.import_module(".".join([self.package, module]))

    #Get all Trigger Modules except for tigger_template
    #Modules need to start with trigger_ and ends with .py
    def getTriggerModules(self):
        dir = os.path.join(sys.path[0], self.package)
        modList = []
        for entry in os.listdir(dir):
            if os.path.isfile(os.path.join(dir,entry)) and not entry == "trigger_template.py" and entry.startswith("trigger_") and entry.endswith(".py"):
                modList.append(os.path.splitext(entry)[0])
        return modList

    @ratelimit.limits(calls=ratelimitCalls, period=ratelimitPeriod)
    def fireIcmpTrigger(self, eth, iph, icmph):
        for mod_name, mod in self.triggers.items():
            if hasattr(mod, 'icmp_trigger'):
                getattr(mod, 'icmp_trigger')(eth, iph, icmph)

    @ratelimit.limits(calls=ratelimitCalls, period=ratelimitPeriod)
    def fireTcpTrigger(self, eth, iph, tcph):
        for mod_name, mod in self.triggers.items():
            if hasattr(mod, 'tcp_trigger'):
                getattr(mod, 'tcp_trigger')(eth, iph, tcph)

    def fireTrigger(self, eth, iph):
        for mod_name, mod in self.triggers.items():
            if hasattr(mod, 'trigger'):
                getattr(mod, 'trigger')(eth, iph)

class Network:
    IP_PROTOCOL = 8
    TCP_PROTOCOL = 6
    ICMP_PROTOCOL = 1

    onlyLocal = False
    localIp = '127.0.0.1'
    localhost = '127.0.0.1'

    local = []
    ignoreTcp = []

    @staticmethod
    def addLocal(item):
        """Add a ip or CIDR to the local network list"""
        tmp = item
        if "/" not in tmp:
            # Change IP to CIDR notation -> /32 is a specifc IP
            tmp = tmp + "/32"
        Network.local.append( ipaddress.IPv4Network(tmp) )

    @staticmethod
    def addLocalRange(list):
        """Add a range of IPs or CIDRs to the local network list"""
        for i in list:
            Network.addLocal(i)

    @staticmethod
    def isLocal(ip):
        """Checks if the IP is in the local network list"""
        ip = ipaddress.IPv4Address(ip)
        for network in Network.local:
            if ip in network:
                return True
        return False

    @staticmethod
    def addTcpIgnore(item):
        """Add a IP and CIDR with port tuple to the TCP ignore list (For port -> none == any port)"""
        # If not a CIDR notation
        tmp = item[0]
        if "/" not in tmp:
            # Change IP to CIDR notation -> /32 is a specifc IP
            tmp = tmp + "/32"
        Network.ignoreTcp.append( (ipaddress.IPv4Network(tmp), item[1]) )
    
    @staticmethod
    def addTcpIgnoreRange(list):
        """Adds IPs and CIDRs with there port tuples to the TCP ignore list (For port -> none == any port)"""
        for i in list:
            Network.addTcpIgnore(i)

class EthernetHeader:
    """Class to process a packet to EthernetHeader"""
    length = 14

    #Parse the EthernetHeader 
    def __init__(self, packet):
        self.header = packet[:self.length]
        self.unpacked = struct.unpack('!6s6sH' , self.header)
        self.protocol = socket.ntohs(self.unpacked[2])
        self.src_mac = EthernetHeader.ethAddr(packet[0:6])
        self.dest_mac = EthernetHeader.ethAddr(packet[0:6])

    @staticmethod
    def ethAddr(p) :
        """Convert integer array to hex mac address"""
        return ':'.join(format(x, '02x') for x in p)

class IpHeader:
    """Class to process a packet to IpHeader"""
    #Parse the IpHeader 
    #https://datatracker.ietf.org/doc/html/rfc791
    def __init__(self, packet):
        raw = packet[EthernetHeader.length:(20+EthernetHeader.length)]
        self.unpacked = struct.unpack('!BBHHHBBH4s4s' , raw)
        version_length = self.unpacked[0]
        self.version = version_length >> 4
        self.length = (version_length & 0xF) * 4
        self.ttl = self.unpacked[5]
        self.protocol = self.unpacked[6]
        self.src_addr = str(socket.inet_ntoa(self.unpacked[8]))
        self.dest_addr = str(socket.inet_ntoa(self.unpacked[9]))

class TcpHeader:
    """Class to process a packet to TcpHeader"""
    #Parse the Tcp Header
    #https://datatracker.ietf.org/doc/html/rfc793
    def __init__(self, iph, packet):
        rawLength = iph.length + EthernetHeader.length
        raw = packet[rawLength:rawLength+20]
        self.unpacked = struct.unpack('!HHLLBBHHH' , raw)
        self.src_port = self.unpacked[0]
        self.dest_port = self.unpacked[1]
        self.sequence = self.unpacked[2]
        self.acknowledgement = self.unpacked[3]
        self.length = self.unpacked[4] >> 4
        size = EthernetHeader.length + iph.length + self.length * 4
        self.size = len(packet) - size
        self.data = packet[size:]

class IcmpHeader:
    """Class to process a packet to IcmpHeader"""
    #Parse the Icmp Header
    #https://datatracker.ietf.org/doc/html/rfc792
    def __init__(self, iph, packet):
        rawLength = iph.length + EthernetHeader.length
        self.size = rawLength + 4
        self.unpacked = struct.unpack('!BBH' , packet[rawLength:rawLength+4])
        self.type = self.unpacked[0]
        self.code = self.unpacked[1]
        self.checksum = self.unpacked[2]
        self.dataSize = len(packet) - self.size
        self.data = packet[self.dataSize:]

# Get Local Ip automagically
def autoLocalIp(knownHost):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((knownHost, 80))
            return sock.getsockname()[0]
    except Exception:
        logging.critical("Could not get local IP automagically, please use the override config")
        sys.exit()

def loadConfig(file):
    """Load Config.py and send the variables the right way, also loads trigger modules and setting up logging"""
    logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s", datefmt='%Y-%m-%d, %H:%M:%S')
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)

    try:
        config = importlib.import_module("config")
    except Exception:
        logging.critical("Could not load config")
        exit()
    
    if hasattr(config, "consoleLogLevel"):
        consoleHandler.setLevel( getattr(config, "consoleLogLevel") )

    if hasattr(config, "fileLogging") and getattr(config, "fileLogging") and hasattr(config, "fileLog"):
        fileHandler = logging.FileHandler(getattr(config, "fileLog"), mode='a')
        fileHandler.setFormatter(logFormatter)
        rootLogger.addHandler(fileHandler)

    if hasattr(config, "fileLogLevel"):
        fileHandler.setLevel( getattr(config, "fileLogLevel") )

    if hasattr(config, "localIpOverride"):
        Network.localIp = getattr(config, "localIpOverride")
    else:
        if hasattr(config, "knownHost"):
            Network.localIp = autoLocalIp( getattr(config, "knownHost") )
            logging.info("Own IP is %s" % Network.localIp)
        else:
            logging.error("Could not get local ip, config is wrong, knownHost and localIpOverride isn't set")
    
    if hasattr(config, "tcpIgnoreList"):
        Network.addTcpIgnoreRange( getattr(config, "tcpIgnoreList") )

    if hasattr(config, "localIpList"):
        Network.addLocalRange( getattr(config, "localIpList") )

def main() -> None:
    loadConfig("config")
    tripwire = Tripwire()
    
    # Create Sniff Socket
    try:
        sock = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except socket.error as msg:
        try:
            logging.critical('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        except Exception:
            logging.critical('Socket could not be created. Root privilege is needed. Please run again as root.')
        sys.exit()

    logging.info("Sniffer is running..")

    while True:
        #Receive a packet
        packet = sock.recvfrom(65565)[0]

        #Parse Ethernet Header
        eth = EthernetHeader(packet)

        if eth.protocol == Network.IP_PROTOCOL:
            #Parse IP Header
            iph = IpHeader(packet)

            #Traffic is not meant for this machine -> skip
            if iph.dest_addr != Network.localIp and iph.src_addr != Network.localIp:
                continue
            
            #Traffic is internal -> skip
            if iph.dest_addr == Network.localhost or iph.src_addr == Network.localhost:
                continue
            
            # Only Local check, if this option is turned on and when it is not traffic from the local network -> skip
            if Network.onlyLocal and (not Network.isLocal(iph.dest_addr) or not Network.isLocal(iph.src_addr)):
                continue

            #TCP protocol
            if iph.protocol == Network.TCP_PROTOCOL:
                #Parse TCP packet
                tcph = TcpHeader(iph, packet)

                skip = False
                for ignore in Network.ignoreTcp:
                    if ipaddress.IPv4Address(iph.dest_addr) in ignore[0] or ipaddress.IPv4Address(iph.src_addr) in ignore[0]:
                        if ignore[1] is None or tcph.dest_port == ignore[1] or tcph.src_port == ignore[1]:
                            skip = True
                            break
                if skip:
                    continue

                #Packet tries to establish a new TCP connection to the machine -> Trigger
                if iph.src_addr != Network.localIp and tcph.acknowledgement == 0x00:
                    logging.info("TCP-Trigger by " + iph.src_addr + " (" + eth.src_mac + ") on Port " + str(tcph.dest_port))
                    tripwire.fireTrigger(eth, iph)
                    try:
                        tripwire.fireTcpTrigger(eth, iph, tcph)
                    except ratelimit.exception.RateLimitException:
                        pass

            #ICMP Packets
            elif iph.protocol == Network.ICMP_PROTOCOL: 
                #Parse ICMP packet
                icmph = IcmpHeader(iph, packet)

                #Not the local machine is asking for a Timestamp, Information Request or Echo -> Trigger
                if iph.src_addr != Network.localIp and (icmph.type == 13 or icmph.type == 15 or icmph.type == 8):
                    logging.info("ICMP-Trigger by " + iph.src_addr + " (" + eth.src_mac + ") of Type " + str(icmph.type))
                    tripwire.fireTrigger(eth, iph)
                    try:
                        tripwire.fireIcmpTrigger(eth, iph, icmph)
                    except ratelimit.exception.RateLimitException:
                        pass

if __name__ == "__main__":
    main()
