import logging

# IP of this machine in the network you want to monitor
# will be figured out automatically
# if you don't want that enter your IP in localIpOverride
# uncomment localIpOverride if you want to set it manually
#localIpOverride = '127.0.0.1'
knownHost = '8.8.8.8'

# Only monitor connections set in localNetwork = True
#    Enough for most usecases I guess
#
# Monitor all connection = False
#    This will need tweeking in ignoreTcpList
onlyLocal = True

# TCP requests to ('IP or CIDR', PORT) will be ignored and skipped
# These will not fire a trigger
# Ports: None == All Ports are ignored
tcpIgnoreList = [
   #('192.168.178.39', 22222),   # My PC i use for SSH and 22222 is my SSH Port
   #('192.168.178.1', 14013),    # Fritz!box Childprotection, isn't even turned on in my router, thanks (•_•)
   #('91.189.92.0/24', None),    # Ubuntu Update Service
]

# List of local networks
# In most cases this doesn't need any changes
localIpList = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# Avoid a DoS limiting the times a trigger can activate (ratelimitCalls) in a time period (ratelimitPeriod)
ratelimitCalls = 5
ratelimitPeriod = 10


consoleLogLevel = logging.INFO

fileLogging = True
fileLogLevel = logging.DEBUG
fileLog = "/var/log/tripwire.log"
