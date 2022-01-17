import socket
import threading
import requests

#
# CONFIG
#

# Any Host that is reachable for you on port 80 could also be your router, pihole or whatever
knownHost = '8.8.8.8' 

# Listen for ICMP request, e.g. NMAP, would be a early response
shouldSetIcmpWire = True
# Listen on ports defined in ports
shouldSetPortWire = True

ports = [
    20,    # FTP Data Transfer
    21,    # FTP Command Control
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    119,   # NNTP
    123,   # NTP
    143,   # IMAP
    161,   # SNMP
    194,   # IRC
    443,   # HTTPS
    3306,  # MySQL Default port
    27017, # MongoDB Default port
]

#Put your telegram stuff here
telegram_botToken = 'TOKEN'
telegram_chatId   = 'CHATID'

#
# CONFIG END
#

#Resolves your network IP
def GetLocalIP(knownHost):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((knownHost, 80))
        return sock.getsockname()[0]

def PortWire(host, port) -> None:
    threading.Thread(target=PortWireHandle, args=(host, port,)).start()

#Listens to a port, if anything connects it triggers
def PortWireHandle(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen(1)
        print("Portwire on Port " + str(port) + " is set.")

        while True:
            conn, addr = sock.accept()
            trigger("Port-Wire was tripped by "+ str(addr[0]) + " on Port " + str(port))
            conn.close()

def IcmpWire() -> None:
    threading.Thread(target=IcmpWireHandle, args=()).start()

#Listens to Icmp Requests e.g. NMAP and triggers if any request is received
def IcmpWireHandle():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        print("ICMP-Wire is set")

        while True:
            _, addr = sock.recvfrom(1024)
            trigger("ICMP-Wire was tripped by "+ str(addr[0]))

def telegram_message(message):
    global telegram_botToken, telegram_chatId
    sendText = 'https://api.telegram.org/bot' + telegram_botToken + '/sendMessage?chat_id=' + telegram_chatId + '&parse_mode=Markdown&text=' + message
    response = requests.get(sendText)
    return response.json()

#This should happen on any trigger
def trigger(message):
    print(message)
    telegram_message(message)

def main() -> None:
    #Setting Port wires
    if shouldSetPortWire:
        localIp = GetLocalIP(knownHost)
        for port in ports:
            PortWire(localIp, port)

    #Setting Icmp wires
    if shouldSetIcmpWire:
        IcmpWire()
        
    print("All Tripwires are set, waiting for action..")

if __name__ == "__main__":
    main()