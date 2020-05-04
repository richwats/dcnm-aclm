import re
import ipaddress
import logging
import json
import hashlib

from utils import ipfunctions

class acl_entry():
    """docstring for ."""

    validName = "[a-zA-Z0-9_\-]{1,64}"
    validTypes = ['permit', 'deny', 'remark']
    validProtocols = ['ip','tcp','udp','icmp']
    #validProtocols = ['ahp','eigrp','esp','gre','icmp','igmp','ip','nos','ospf','pcp','pim','tcp','udf','udp']
    """
    <0-255>  A protocol number
    ahp      Authentication header protocol
    eigrp    Cisco's EIGRP routing protocol
    esp      Encapsulation security payload
    gre      Cisco's GRE tunneling
    icmp     Internet Control Message Protocol
    igmp     Internet Group Management Protocol
    ip       Any IP protocol
    nos      KA9Q NOS compatible IP over IP tunneling
    ospf     OSPF routing protocol
    pcp      Payload compression protocol
    pim      Protocol independent multicast
    tcp      Transmission Control Protocol
    udf      User defined field match
    udp      User Datagram Protocol
    """

    validOperators = ['eq','gt','lt','neq','range']
    """
    eq           Match only packets on a given port number
    gt           Match only packets with a greater port number
    lt           Match only packets with a lower port number
    neq          Match only packets not on a given port number
    portgroup    Src port group
    range        Match only packets in the range of port numbers
    """

    """
    bgp          Border Gateway Protocol (179)
    chargen      Character generator (19)
    cmd          Remote commands (rcmd, 514)
    daytime      Daytime (13)
    discard      Discard (9)
    domain       Domain Name Service (53)
    drip         Dynamic Routing Information Protocol (3949)
    echo         Echo (7)
    exec         Exec (rsh, 512)
    finger       Finger (79)
    ftp          File Transfer Protocol (21)
    ftp-data     FTP data connections (20)
    gopher       Gopher (70)
    hostname     NIC hostname server (101)
    ident        Ident Protocol (113)
    irc          Internet Relay Chat (194)
    klogin       Kerberos login (543)
    kshell       Kerberos shell (544)
    login        Login (rlogin, 513)
    lpd          Printer service (515)
    nntp         Network News Transport Protocol (119)
    pim-auto-rp  PIM Auto-RP (496)
    pop2         Post Office Protocol v2 (109)
    pop3         Post Office Protocol v3 (110)
    smtp         Simple Mail Transport Protocol (25)
    sunrpc       Sun Remote Procedure Call (111)
    tacacs       TAC Access Control System (49)
    talk         Talk (517)
    telnet       Telnet (23)
    time         Time (37)
    uucp         Unix-to-Unix Copy Program (540)
    whois        Nicname (43)
    www          World Wide Web (HTTP, 80)
    """

    validTcpPortNames = {
    'bgp':179,
    'chargen': 19,
    'cmd': 514,
    'daytime': 13,
    'discard': 9,
    'domain': 53,
    'drip': 3949,
    'echo': 7,
    'exec': 512,
    'finger': 79,
    'ftp': 21,
    'ftp-data': 20,
    'gopher': 70,
    'hostname': 101,
    'ident': 113,
    'irc': 194,
    'klogin': 543,
    'kshell': 544,
    'login': 513,
    'lpd': 515,
    'nntp': 119,
    'pim-auto-rp': 496,
    'pop2': 109,
    'pop3': 110,
    'smtp': 25,
    'sunrpc': 111,
    'tacacs': 49,
    'talk': 517,
    'telnet': 23,
    'time': 37,
    'uucp': 540,
    'whois': 43,
    'www': 80
    }

    reverseTcpPortNames = {
    179: 'bgp',
    19: 'chargen',
    514: 'cmd',
    13: 'daytime',
    9: 'discard',
    53: 'domain',
    3949: 'drip',
    7: 'echo',
    512: 'exec',
    79: 'finger',
    21: 'ftp',
    20: 'ftp-data',
    70: 'gopher',
    101: 'hostname',
    113: 'ident',
    194: 'irc',
    543: 'klogin',
    544: 'kshell',
    513: 'login',
    515: 'lpd',
    119: 'nntp',
    496: 'pim-auto-rp',
    109: 'pop2',
    110: 'pop3',
    25: 'smtp',
    111: 'sunrpc',
    49: 'tacacs',
    517: 'talk',
    23: 'telnet',
    37: 'time',
    540: 'uucp',
    43: 'whois',
    80: 'www'
    }

    """
    biff           Biff (mail notification, comsat, 512)
    bootpc         Bootstrap Protocol (BOOTP) client (68)
    bootps         Bootstrap Protocol (BOOTP) server (67)
    discard        Discard (9)
    dnsix          DNSIX security protocol auditing (195)
    domain         Domain Name Service (DNS, 53)
    echo           Echo (7)
    isakmp         Internet Security Association and Key Management Protocol (500)
    mobile-ip      Mobile IP registration (434)
    nameserver     IEN116 name service (obsolete, 42)
    netbios-dgm    NetBios datagram service (138)
    netbios-ns     NetBios name service (137)
    netbios-ss     NetBios session service (139)
    non500-isakmp  Internet Security Association and Key Management Protocol (4500)
    ntp            Network Time Protocol (123)
    pim-auto-rp    PIM Auto-RP (496)
    rip            Routing Information Protocol (router, in.routed, 520)
    snmp           Simple Network Management Protocol (161)
    snmptrap       SNMP Traps (162)
    sunrpc         Sun Remote Procedure Call (111)
    syslog         System Logger (514)
    tacacs         TAC Access Control System (49)
    talk           Talk (517)
    tftp           Trivial File Transfer Protocol (69)
    time           Time (37)
    who            Who service (rwho, 513)
    xdmcp          X Display Manager Control Protocol (177)
    """

    validUdpPortNames = {
    'biff': 512,
    'bootpc': 68,
    'bootps': 67,
    'discard': 9,
    'dnsix': 195,
    'domain': 53,
    'echo': 7,
    'isakmp': 500,
    'mobile-ip': 434,
    'nameserver': 42,
    'netbios-dgm': 138,
    'netbios-ns': 137,
    'netbios-ss': 139,
    'non500-isakmp': 4500,
    'ntp': 123,
    'pim-auto-rp': 496,
    'rip': 520,
    'snmp': 161,
    'snmptrap': 162,
    'sunrpc': 111,
    'syslog': 514,
    'tacacs': 49,
    'talk': 517,
    'tftp': 69,
    'time': 37,
    'who': 513,
    'xdmcp': 177
    }

    reverseUdpPortNames = {
    512: 'biff',
    68: 'bootpc',
    67: 'bootps',
    9: 'discard',
    195: 'dnsix',
    53: 'domain',
    7: 'echo',
    500: 'isakmp',
    434: 'mobile-ip',
    42: 'nameserver',
    138: 'netbios-dgm',
    137: 'netbios-ns',
    139: 'netbios-ss',
    4500: 'non500-isakmp',
    123: 'ntp',
    496: 'pim-auto-rp',
    520: 'rip',
    161: 'snmp',
    162: 'snmptrap',
    111: 'sunrpc',
    514: 'syslog',
    49: 'tacacs',
    517: 'talk',
    69: 'tftp',
    37: 'time',
    513: 'who',
    177: 'xdmcp'
    }

    ## Flags not used yet

    validIpFlags = ['log']
    """
    dscp                  Match packets with given dscp value
    fragments             Check non-initial fragments
    packet-length         Match packets based on layer 3 packet length
    precedence            Match packets with given precedence value
    redirect              Redirect to interface(s). Syntax example: redirect Ethernet1/1,Ethernet1/2,port-channel1
    set-erspan-dscp       Syntax: set-erspan-dscp; Set ERSPAN outer IP DSCP value <1-63>
    set-erspan-gre-proto  Syntax: set-erspan-gre-proto; Set ERSPAN GRE protocol <1-65535>
    time-range            Specify a time range
    ttl                   Match Packets with a given TTL value
    udf                   User defined field match
    vlan                  Configure match based on vlan
    log                   Log matches against this entry
    """

    validTcpFlags = ['log']
    """
    ack                            Match on the ACK bit
    dscp                           Match packets with given dscp value
    established                    Match established connections
    fin                            Match on the FIN bit
    http-method                    Match packets based on http-method
    packet-length                  Match packets based on layer 3 packet length
    precedence                     Match packets with given precedence value
    psh                            Match on the PSH bit
    redirect                       Redirect to interface(s). Syntax example: redirect Ethernet1/1,Ethernet1/2,port-channel1
    rst                            Match on the RST bit
    set-erspan-dscp                Syntax: set-erspan-dscp; Set ERSPAN outer IP DSCP value <1-63>
    set-erspan-gre-proto           Syntax: set-erspan-gre-proto; Set ERSPAN GRE protocol <1-65535>
    syn                            Match on the SYN bit
    tcp-flags-mask (no abbrev)     Specify TCP Flags
    tcp-option-length (no abbrev)  Specify TCP Options size
    time-range                     Specify a time range
    ttl                            Match Packets with a given TTL value
    udf                            User defined field match
    urg                            Match on the URG bit
    vlan                           Configure match based on vlan
    log                            Log matches against this entry
    """

    validUdpFlags = ['log']
    """
    dscp                  Match packets with given dscp value
    nve                   VNI ID <0-16777215>
    packet-length         Match packets based on layer 3 packet length
    precedence            Match packets with given precedence value
    redirect              Redirect to interface(s). Syntax example: redirect Ethernet1/1,Ethernet1/2,port-channel1
    set-erspan-dscp       Syntax: set-erspan-dscp; Set ERSPAN outer IP DSCP value <1-63>
    set-erspan-gre-proto  Syntax: set-erspan-gre-proto; Set ERSPAN GRE protocol <1-65535>
    time-range            Specify a time range
    ttl                   Match Packets with a given TTL value
    udf                   User defined field match
    vlan                  Configure match based on vlan
    log                   Log matches against this entry
    """

    validIcmpFlags = []
    """
    <0-255>                      ICMP message type
    administratively-prohibited  Administratively prohibited
    alternate-address            Alternate address
    conversion-error             Datagram conversion
    dod-host-prohibited          Host prohibited
    dod-net-prohibited           Net prohibited
    dscp                         Match packets with given dscp value
    echo                         Echo (ping)
    echo-reply                   Echo reply
    fragments                    Check non-initial fragments
    general-parameter-problem    Parameter problem
    host-isolated                Host isolated
    host-precedence-unreachable  Host unreachable for precedence
    host-redirect                Host redirect
    host-tos-redirect            Host redirect for TOS
    host-tos-unreachable         Host unreachable for TOS
    host-unknown                 Host unknown
    host-unreachable             Host unreachable
    information-reply            Information replies
    information-request          Information requests
    mask-reply                   Mask replies
    mask-request                 Mask requests
    mobile-redirect              Mobile host redirect
    net-redirect                 Network redirect
    net-tos-redirect             Net redirect for TOS
    net-tos-unreachable          Network unreachable for TOS
    net-unreachable              Net unreachable
    network-unknown              Network unknown
    no-room-for-option           Parameter required but no room
    option-missing               Parameter required but not present
    packet-length                Match packets based on layer 3 packet length
    packet-too-big               Fragmentation needed and DF set
    parameter-problem            All parameter problems
    port-unreachable             Port unreachable
    precedence                   Match packets with given precedence value
    precedence-unreachable       Precedence cutoff
    protocol-unreachable         Protocol unreachable
    reassembly-timeout           Reassembly timeout
    redirect                     Redirect to interface(s). Syntax example: redirect Ethernet1/1,Ethernet1/2,port-channel1
    redirect                     All redirects
    router-advertisement         Router discovery advertisements
    router-solicitation          Router discovery solicitations
    set-erspan-dscp              Syntax: set-erspan-dscp; Set ERSPAN outer IP DSCP value <1-63>
    set-erspan-gre-proto         Syntax: set-erspan-gre-proto; Set ERSPAN GRE protocol <1-65535>
    source-quench                Source quenches
    source-route-failed          Source route failed
    time-exceeded                All time exceededs
    time-range                   Specify a time range
    timestamp-reply              Timestamp replies
    timestamp-request            Timestamp requests
    traceroute                   Traceroute
    ttl                          Match Packets with a given TTL value
    ttl-exceeded                 TTL exceeded
    unreachable                  All unreachables
    vlan                         Configure match based on vlan
    log                          Log matches against this entry
    """
    # aclType = None
    # aclProtocol = None
    # remarks = None
    # sourceIpMask = None
    # destIpMask = None
    # sourceOperator = None
    # sourcePortStart = None
    # sourcePortStop = None
    # destOperator = None
    # destPortStart = None
    # destPortStop = None
    # extra = None


    # Examples
    # 10 permit ip 1.1.1.1/32 any
    # 20 permit tcp 3.0.0.0/8 255.0.0.0 eq 1500
    # 25 deny udp any any eq 500
    # 26 deny tcp any eq 490 any

    ## kwargs
    def __init__(self, **kwargs ):
        #self.arg = arg
        # self.aclType = aclType
        # self.aclProtocol = aclProtocol
        # self.sourceIP = sourceIP
        # self.sourcePort = sourcePort
        # self.destIP = destIP
        # self.destPort = destPort

        ## Reset
        self.aclType = None
        self.aclProtocol = None
        self.remarks = None
        self.sourceIpMask = None
        self.destIpMask = None
        self.sourceOperator = None
        self.sourcePortStart = None
        self.sourcePortStop = None
        self.destOperator = None
        self.destPortStart = None
        self.destPortStop = None
        self.extra = None

        return

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)
        #return self.__dict__

    def toJson(self):
        return json.dumps(self.__dict__,default=str)

    def json(self):
        return json.dumps(self.__dict__,default=str)

    def toDict(self):
        logging.debug("[acl_entry][toDict] __dict__: {}".format(self.__dict__))
        return self.__dict__

    def output(self):
        output = """
        ------------------------
        Entry Type: {}
        Protocol: {}
        Remark: {}
        Source IP/Mask: {}
        Source Port Operator {}
        Source Port Start: {}
        Source Port Stop: {}
        Destination IP/Mask: {}
        Destination Port Operator: {}
        Destination Port Start: {}
        Destination Port Stop: {}
        Extra: {}
        ------------------------
        """.format(
        self.aclType,
        self.aclProtocol,
        self.remarks,
        self.sourceIpMask,
        self.sourceOperator,
        self.sourcePortStart,
        self.sourcePortStop,
        self.destIpMask,
        self.destOperator,
        self.destPortStart,
        self.destPortStop,
        self.extra
        )
        return output


    def toCli(self):
        ## Reconstruct to CLI
        msg = ""

        ## Remark
        if self.aclType == "remark":
            msg = "{} {}".format(self.aclType, self.remarks)
            return msg

        ## "any" handling
        if self.sourceIpMask == "0.0.0.0/0":
            self.sourceIpMask = "any"

        if self.destIpMask == "0.0.0.0/0":
            self.destIpMask = "any"

        ## "host" handling
        if ipfunctions.isIpV4AdddressHost(self.sourceIpMask):
            sourceIP = ipaddress.IPv4Network(self.sourceIpMask).network_address
            ## Don't want to change - just display!!
            dispSourceIpMask = "host {}".format(sourceIP)
        else:
            dispSourceIpMask = self.sourceIpMask

        if ipfunctions.isIpV4AdddressHost(self.destIpMask):
            destIP = ipaddress.IPv4Network(self.destIpMask).network_address
            ## Don't want to change - just display!!
            dispDestIpMask = "host {}".format(destIP)
        else:
            dispDestIpMask = self.destIpMask


        ## Use Defined Port Names
        logging.debug("[acl_entry][toCli] Message Processing - ACL Protocol: {}".format(self.aclProtocol))
        outputSourcePortStart = self.sourcePortStart
        outputSourcePortStop = self.sourcePortStop
        outputDestPortStart = self.destPortStart
        outputDestPortStop = self.destPortStop
        if self.aclProtocol == "tcp":
            logging.debug("[acl_entry][toCli] Message Processing - TCP Ports: {} {} {} {}".format(self.sourcePortStart,self.sourcePortStop,self.destPortStart,self.destPortStop))
            if self.sourcePortStart != None and self.reverseTcpPortNames.get(int(self.sourcePortStart)) != None:
                outputSourcePortStart = self.reverseTcpPortNames.get(int(self.sourcePortStart))
            if self.sourcePortStop != None and self.reverseTcpPortNames.get(int(self.sourcePortStop)) != None:
                outputSourcePortStop = self.reverseTcpPortNames.get(int(self.sourcePortStop))
            if self.destPortStart != None and self.reverseTcpPortNames.get(int(self.destPortStart)) != None:
                outputDestPortStart = self.reverseTcpPortNames.get(int(self.destPortStart))
            if self.destPortStop != None and self.reverseTcpPortNames.get(int(self.destPortStop)) != None:
                outputDestPortStop = self.reverseTcpPortNames.get(int(self.destPortStop))
        elif self.aclProtocol == "udp":
            logging.debug("[acl_entry][toCli] Message Processing - UDP Ports: {} {} {} {}".format(self.sourcePortStart,self.sourcePortStop,self.destPortStart,self.destPortStop))
            #logging.debug("[acl_entry][toCli] Message Processing - UDP Lookup: {} - {}".format(self.sourcePortStart, self.reverseUdpPortNames))
            if self.sourcePortStart != None and self.reverseUdpPortNames.get(int(self.sourcePortStart)) != None:
                outputSourcePortStart = self.reverseUdpPortNames.get(int(self.sourcePortStart))
            if self.sourcePortStop != None and self.reverseUdpPortNames.get(int(self.sourcePortStop)) != None:
                outputSourcePortStop = self.reverseUdpPortNames.get(int(self.sourcePortStop))
            if self.destPortStart != None and self.reverseUdpPortNames.get(int(self.destPortStart)) != None:
                outputDestPortStart = self.reverseUdpPortNames.get(int(self.destPortStart))
            if self.destPortStop != None and self.reverseUdpPortNames.get(int(self.destPortStop)) != None:
                outputDestPortStop = self.reverseUdpPortNames.get(int(self.destPortStop))

        ## Source Port Range
        if self.sourcePortStart != None and self.sourcePortStop != None:
            msg = "{} {} {} range {} {}".format(self.aclType, self.aclProtocol, dispSourceIpMask, outputSourcePortStart, outputSourcePortStop )
        ## Source Port
        elif self.sourcePortStart != None and self.sourcePortStop == None:
            msg = "{} {} {} {} {}".format(self.aclType, self.aclProtocol, dispSourceIpMask, self.sourceOperator, outputSourcePortStart )
        ## No Source Port
        else:
            msg = "{} {} {}".format(self.aclType, self.aclProtocol, dispSourceIpMask)

        logging.debug("[acl_entry][toCli] Message Processing - Source: {}".format(msg))
        ## Destination Port Range
        if self.destPortStart != None and self.destPortStop != None:
            msg = msg + " {} range {} {}".format(dispDestIpMask, outputDestPortStart, outputDestPortStop)
        ## Destination Port
        elif self.destPortStart != None and self.destPortStop == None:
            msg = msg + " {} {} {}".format(dispDestIpMask, self.destOperator, outputDestPortStart)
        ## No Destination Port
        else:
            msg = msg + " {}".format(dispDestIpMask)

        ## Log
        try:
            if "log" in self.extra:
                msg = msg + " {}".format("log")
        except:
            pass

        logging.debug("[acl_entry][toCli] Message Processing - Source & Destination: {}".format(msg))

        return msg


class acl_group():
    """docstring for ."""

    # name = ""
    # interval = 10
    # entries = {}
    # hash = None
    # cli = None

    """
    Initialised from "fromCli" or "fromJson"
    """

    def __init__(self, name = None):
        ## Reset
        self.name = ""
        self.interval = 10
        self.entries = {}
        self.hash = None
        self.cli = None

        ## Set Name
        self.name = name

    def __str__(self):
        return self.json()

    def getLastEntry(self):
        keylist = list(self.entries.keys())
        if len(keylist) > 0:
            return max(keylist)
        else:
            return 0

    def getNewAclObject(self):
        return acl_entry()

    def insertRow(self, row, position = 0 ):
        if position == 0:
            position = self.getLastEntry() + self.interval
        self.entries[position] = row
        #self.generateHash() - moved to fromJson & fromCli
        return

    def removeRow(self, position):
        row = self.entries.pop(position, None)
        ### Generate CLI
        self.toCli()
        ## Generate Hash
        self.generateHash()
        return row

    def getRow(self, position):
        row = self.entries[position]
        return row

    def reorder(self):
        newEntries = {}
        sorted(self.entries)
        position = 0
        for k,v in self.entries.items():
            position = position + self.interval
            newEntries[position] = v
        self.entries = newEntries
        sorted(self.entries)

        self.toCli() # needed?
        self.generateHash() # needed?

        return

    def extractIPv4NetMask(self, content):
        """
        Return IPv4 Address Object & Remaining Content List
        """
        ## host, any

        ## Host detection
        if content[0] == "host":
            address = ipaddress.IPv4Network(content[1])
            content = content[2:]
            logging.debug("[acl_group][extractIPv4NetMask] Address: {}".format(address))

        elif content[0] == "any":
            address = ipaddress.IPv4Network('0.0.0.0/0')
            content = content[1:]
            logging.debug("[acl_group][extractIPv4NetMask] Address: {}".format(address))

        ## Network Subnet Detection - Subnet Mask
        elif ipfunctions.isIpV4Adddress(content[0]) and ipfunctions.isSubnetMask(content[1]):
            logging.debug("[acl_group][extractIPv4NetMask] Address in Network|Mask Notation")
            address = ipaddress.IPv4Network((content[0],content[1]))
            content = content[2:]
            logging.debug("[acl_group][extractIPv4NetMask] Address: {}".format(address))

        ## Network Subnet Detection - Wildcard Mask
        elif ipfunctions.isIpV4Adddress(content[0]) and ipfunctions.isWildcardMask(content[1]):
            logging.debug("[acl_group][extractIPv4NetMask] Address in Network|Mask Notation")
            address = ipaddress.IPv4Network((content[0],content[1]))
            content = content[2:]
            logging.debug("[acl_group][extractIPv4NetMask] Address: {}".format(address))

        ## Network/MaskLen Detection
        elif ipfunctions.isIpV4AdddressMask(content[0]):
            logging.debug("[acl_group][extractIPv4NetMask] Address in Network/Length Notation")
            address = ipaddress.IPv4Network(content[0])
            content = content[1:]
            logging.debug("[acl_group][extractIPv4NetMask] Address: {}".format(address))

        else:
            raise Exception('Address Not Determined')

        return address,content

    def extractPortRange(self, content, aclType = None):
        # Get list of valid operators
        validOperators = acl_entry.validOperators

        if content[0] in validOperators:
            logging.debug("[acl_group][extractPortRange] Port Operator: {}".format(content[0]))
            portOperator = content[0]

            ## Port Range?
            if portOperator == "range":
                ## Check Valid Port
                if int(content[1]) <= 65535 and int(content[2]) <= 65535:
                    portStart = content[1]
                    portStop = content[2]
                    content = content[3:]
                    logging.debug("[acl_group][extractPortRange] Port Range: {} - {}".format(portStart, portStop))
                else:
                    raise Exception('Port Out of Valid Range')

            else:
                ## Check Valid Port
                if type(content[1]) == int() and int(content[1]) <= 65535:
                    portStart = content[1]
                    portStop = None
                    content = content[2:]
                    logging.debug("[acl_group][extractPortRange] Source Port: {}".format(portStart))
                elif aclType == "tcp" and content[1] != None:
                    if content[1] in list(acl_entry.validTcpPortNames.keys()):
                        content[1] = acl_entry.validTcpPortNames[content[1]]
                    portStart = content[1]
                    portStop = None
                    content = content[2:]
                elif aclType == "udp" and content[1] != None:
                    if content[1] in list(acl_entry.validUdpPortNames.keys()):
                        content[1] = acl_entry.validUdpPortNames[content[1]]
                    portStart = content[1]
                    portStop = None
                    content = content[2:]
                else:
                    raise Exception("Port Out of Valid Range")

            return portOperator, portStart, portStop, content

        else:
            logging.debug("[acl_group][extractPortRange] No Port Filter Detected")
            return None, None, None, content

    def toCli(self):
        ## Note: Adds extra \n
        output = "ip access-list {}\n".format(self.name)
        sorted(self.entries)
        for k,v in self.entries.items():
            if k == None:
                continue
            output = output + "  {} {}\n".format(k, v.toCli())

        ### Build CLI
        self.cli = output

        return output # may not be needed

    def toDict(self):
        sorted(self.entries)
        output = {}
        output['name'] = self.name
        output['hash'] = self.hash
        output['entries'] = {}
        for k,v in self.entries.items():
            output['entries'][k] = v.toDict()
        logging.debug("[acl_group][toDict] ACL Dict: {}".format(output))
        return output

    def toJson(self, pretty = False):
        sorted(self.entries)
        jsonDict = {}
        jsonDict['name'] = self.name
        jsonDict['hash'] = self.hash
        jsonDict['entries'] = {}
        for k,v in self.entries.items():
            jsonDict['entries'][k] = v.toDict()
        #logging.info(json.dumps(jsonDict))
        if pretty:
            return json.dumps(jsonDict, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            logging.debug("[acl_group][toJson] ACL JSON: {}".format(jsonDict))
            # logging.debug("[acl_group][toJson] JSON: {}".format(json.dumps(jsonDict)))
            return json.dumps(jsonDict)
            #return jsonDict

    def json(self, pretty = False):
        return self.toJson(pretty)

    # def fromJson(self, jsonInput):
    #     """
    #     Build ACL Object from JSON
    #     ASSUMES VALID JSON!
    #     """
    #     self.name = jsonInput['name']
    #     self.hash = jsonInput['hash']
    #     self.entries = jsonInput['entries']
    #     return

    def generateHash(self):
        logging.debug("[acl_group][generateHash] Generating MD5 hash of CLI content")
        # content = str(self.toCli())
        content = self.cli
        logging.debug("[acl_group][generateHash] Content: {}".format(content))
        content = content.encode('utf-8')
        self.hash = hashlib.md5(content).hexdigest()
        logging.debug("[acl_group][generateHash] Hash: {}".format(self.hash))
        return

    def validateName(self, name):
        """
        Test if name is valid
        """
        logging.debug("[acl_group][validateName] Input Name: {}".format(name))
        ## Extract Name
        p = re.compile(acl_entry.validName)
        m = p.match(name)
        if m:
            logging.debug("[acl_group][validateName] Name is valid: {}".format(m))
            return True
        else:
            logging.error("[acl_group][validateName] Name is invalid: {}".format(m))
            return False

    def fromJson(self, input):
        """
        Take full Json ACL, validate and parse to objects
        """
        ### Clear entries
        self.entries = {}

        ## Extract and Validate Name
        if 'name' in list(input.keys()):
            ## NO VALIDATION!!
            if self.validateName(input['name']):
                self.name = input['name']
            else:
                raise Exception("ACL Name is Invalid: {}".format(input['name']))
        else:
            logging.error("[acl_group][fromJson] Unable to extract IP ACL name")
            raise Exception('Unable to extract IP ACL name')

        ## No Entries - Return empty ACL
        if 'entries' not in list(input.keys()):
            self.toCli()
            self.generateHash()
            return

        ## Iterate Entries
        for position, entry in input['entries'].items():

            if position == None or position == "":
                raise Exception('ACL entry position is required')

            newEntry = acl_entry()
            logging.info("[acl_group][fromJson] Processing Position: {} Entry: {}".format(position, entry))

            """
            self.aclType,
            self.aclProtocol,
            self.remarks,
            self.sourceIpMask,
            self.sourceOperator,
            self.sourcePortStart,
            self.sourcePortStop,
            self.destIpMask,
            self.destOperator,
            self.destPortStart,
            self.destPortStop,
            self.extra
            """

            ## Determine Type
            if entry['aclType'] not in newEntry.validTypes:
                logging.error("[acl_group][fromJson] Invalid ACL entry type")
                raise Exception('Invalid ACL entry type')
            else:
                newEntry.aclType = entry['aclType']


            ## Check for remarks
            if newEntry.aclType == "remark":
                newEntry.remarks = entry['remarks']
                logging.debug("[acl_group][fromJson] ACL Remark: {}".format(newEntry.remarks))
                self.insertRow(newEntry, position)
                continue

            ## Determine Protocol
            if entry['aclProtocol'] not in newEntry.validProtocols:
                logging.error("[acl_group][fromJson] Invalid ACL entry protocol")
                raise Exception('Invalid ACL entry protocol')
            else:
                newEntry.aclProtocol = entry['aclProtocol']

            ## "ip" entry handling
            if newEntry.aclProtocol == "ip":
                ## Validate Source IP Addresses
                if ipfunctions.isIpV4AdddressMask(entry['sourceIpMask']):
                    newEntry.sourceIpMask = entry['sourceIpMask']
                else:
                    raise Exception('Invalid Source IP/Mask')

                ## Validate Destination IP Addresses
                if ipfunctions.isIpV4AdddressMask(entry['destIpMask']):
                    newEntry.destIpMask = entry['destIpMask']
                else:
                    raise Exception('Invalid Destination IP/Mask')

                ### Remaining
                if 'extra' in list(entry.keys()):
                    newEntry.extra = entry['extra']
                    logging.debug("[acl_group][fromJson] Extra: {}".format(newEntry.extra))

            ## "icmp" entry handling
            elif newEntry.aclProtocol == "icmp":
                ## Validate Source IP Addresses
                if ipfunctions.isIpV4AdddressMask(entry['sourceIpMask']):
                    newEntry.sourceIpMask = entry['sourceIpMask']
                else:
                    raise Exception('Invalid Source IP/Mask')

                ## Validate Destination IP Addresses
                if ipfunctions.isIpV4AdddressMask(entry['destIpMask']):
                    newEntry.destIpMask = entry['destIpMask']
                else:
                    raise Exception('Invalid Destination IP/Mask')

                ### Remaining
                if 'extra' in list(entry.keys()):
                    newEntry.extra = entry['extra']
                    logging.debug("[acl_group][fromJson] Extra: {}".format(newEntry.extra))


            elif newEntry.aclProtocol == "tcp" or newEntry.aclProtocol == "udp":

                ## Validate IP Addresses
                if ipfunctions.isIpV4AdddressMask(entry['sourceIpMask']):
                    newEntry.sourceIpMask = entry['sourceIpMask']
                else:
                    raise Exception('Invalid Source IP/Mask')

                ### Source Operator
                if entry.get('sourceOperator') != None and entry['sourceOperator'] in newEntry.validOperators:
                    newEntry.sourceOperator = entry['sourceOperator']
                    newEntry.sourcePortStart = entry['sourcePortStart']
                    if entry.get('sourcePortStop'):
                        newEntry.sourcePortStop = entry['sourcePortStop']
                    else:
                        newEntry.sourcePortStop = None

                ## Validate Destination IP Addresses
                if ipfunctions.isIpV4AdddressMask(entry['destIpMask']):
                    newEntry.destIpMask = entry['destIpMask']
                else:
                    raise Exception('Invalid Destination IP/Mask')

                ### Destination Operator
                if entry.get('destOperator') != None and entry['destOperator'] in newEntry.validOperators:
                    newEntry.destOperator = entry['destOperator']
                    newEntry.destPortStart = entry['destPortStart']
                    if entry.get('destPortStop'):
                        newEntry.destPortStop = entry['destPortStop']
                    else:
                        newEntry.destPortStop = None

                ### Remaining
                if 'extra' in list(entry.keys()):
                    newEntry.extra = entry['extra']
                    logging.debug("[acl_group][fromJson] Extra: {}".format(newEntry.extra))

                # ### Sanity Check
                # 30-4-20 "permit tcp any any established" is valid
                # if newEntry.sourceOperator == None and newEntry.destOperator == None:
                #     logging.error("[acl_group][fromJson] L4 Protocol Not Recognised - Skipping Line")
                #     raise Exception('L4 Protocol Not Recognised')

            else:
                ## Type Not Found
                logging.error("[acl_group][fromJson] ACL Protocol Not Recognised - Skipping Line")
                raise Exception('ACL Protocol Not Recognised')

            ## DISPLAY Entry
            logging.info("[acl_group][fromJson] New Entry: {}".format(newEntry))

            ## Add to entries
            self.insertRow(newEntry, position)

        ### Generate CLI
        self.toCli()

        ### Generate Hash
        self.generateHash()

        return

    def fromCli(self, input):
        """
        Take full ACL and parse to objects
        """
        ### Clear entries
        self.entries = {}

        ### Parse Lines
        lines = input.splitlines()
        logging.debug("[acl_group][fromCli] Lines: {}".format(lines))

        ## Extract Name
        p = re.compile('^ip access-list ('+acl_entry.validName+')$')
        m = p.match(lines[0].strip())
        logging.debug("[acl_group][fromCli] Regex Match: {}".format(m.groups()))
        if m != None and m.group(1):
            logging.info("[acl_group][fromCli] Input ACL Name: {}".format(m.group(1)))
            if self.validateName(m.group(1)):
                self.name = m.group(1)

            else:
                raise Exception("ACL Name is Invalid: {}".format(m.group(1)))
        else:
            logging.error("[acl_group][fromJson] Unable to extract IP ACL name")
            raise Exception('Unable to extract IP ACL name')

            #self.name = str(m.group(1))

        if len(lines) == 0:
            ### Generate CLI
            self.toCli()

            ## Generate hash
            self.generateHash()



        # else:
        #     ## Error
        #     logging.error("[acl_group][fromCli] Unable to extract valid IP ACL name")
        #     raise Exception('Unable to extract IP ACL name')
        #     #return

        ## Iterate lines
        for line in lines[1:]:
            newEntry = acl_entry()
            line = line.strip()
            logging.info("[acl_group][fromCli] Processing Line: {}".format(line))
            ##
            words = line.split(" ")
            logging.debug(words)

            ## Determine Entry Number
            p = re.compile('^[0-9]+')
            m = p.match(words[0])
            if m != None and m.group(0):
                 position = int(m.group(0))
                 logging.debug("[acl_group][fromCli] ACL Entry: {}".format(m.group(0)))
            else:
                ##Error
                # No Number
                #raise Error('Unable to extract ACL entry number')
                logging.error("[acl_group][fromCli] Unable to extract ACL entry number - Skipping line: {}".format(words[0]))
                continue

            ## Determine Type
            if words[1] in newEntry.validTypes:
                newEntry.aclType = words[1]
                logging.debug("[acl_group][fromCli] ACL Type: {}".format(words[1]))
            else:
                logging.error("[acl_group][fromCli] Unable to determine ACL entry type - Skipping line")
                continue

            ## Check for remark
            if newEntry.aclType == "remark":
                newEntry.remarks = str(" ").join(words[2:])
                logging.debug("[acl_group][fromCli] ACL Remark: {}".format(newEntry.remarks))
                try:
                    self.insertRow(newEntry, position)
                    continue
                except Exception as e:
                    logging.error("[acl_group][fromCli] Unable to add remark to ACL group: {} - Skipping Line".format(e))
                    continue


            ## Determine Protocol
            if words[2] in newEntry.validProtocols:
                newEntry.aclProtocol = words[2]
                #print("ACL Protocol: {}".format(newEntry.aclProtocol))
                content = words[3:]
            else:
                ## No Protocol Detected
                ## Error
                logging.error("[acl_group][fromCli] Unable to determine ACL entry protocol - Skipping line: {}".format(words[2]))
                continue

            ## "ip" entry handling
            if newEntry.aclProtocol == "ip":

                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.sourceIpMask = str(address)
                except Exception as e:
                    logging.error("[acl_group][fromCli] Source Address Error: {} - Skipping Line".format(e))
                    continue

                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.destIpMask = str(address)
                except Exception as e:
                    logging.error("[acl_group][fromCli] Destination Address Error: {} - Skipping Line".format(e))
                    continue

                ### Remaining
                newEntry.extra = content
                logging.debug("[acl_group][fromCli] Extra: {}".format(newEntry.extra))

            ## "icmp" entry handling
            elif newEntry.aclProtocol == "icmp":

                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.sourceIpMask = str(address)
                except Exception as e:
                    logging.error("[acl_group][fromCli] Source Address Error: {} - Skipping Line".format(e))
                    continue

                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.destIpMask = str(address)
                except Exception as e:
                    logging.error("[acl_group][fromCli] Destination Address Error: {} - Skipping Line".format(e))
                    continue

                ### Remaining
                newEntry.extra = content
                logging.debug("[acl_group][fromCli] Extra: {}".format(newEntry.extra))


            elif newEntry.aclProtocol == "tcp" or newEntry.aclProtocol == "udp":
                ## Lookahead
                # options
                # x.x.x.x/x OP xxx
                # x.x.x.x y.y.y.y OP xxx
                # x.x.x.x/x a.a.a.a/a OP xxx
                # x.x.x.x y.y.y.y a.a.a.a b.b.b.b OP xxx

                ## Source Network
                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.sourceIpMask = str(address)
                except Exception as e:
                    logging.error("[acl_group][fromCli] Source Address Error: {} - Skipping Line".format(e))
                    continue

                ### Source Operator

                try:
                    portOperator, portStart,portStop, content = self.extractPortRange(content, newEntry.aclProtocol)
                    newEntry.sourceOperator = portOperator
                    newEntry.sourcePortStart = portStart
                    newEntry.sourcePortStop = portStop
                    if portStart != None or portStop != None:
                        logging.debug("[acl_group][fromCli] Source Port Range: {} - {}".format(newEntry.sourcePortStart, newEntry.sourcePortStop))
                    else:
                        logging.debug("[acl_group][fromCli] No Source Port Filter Detected - Ignoring")
                except Exception as e:
                    logging.debug("[acl_group][fromCli] Source Port Not Determined - Ignoring.  Error: {}".format(e))
                    # logging.error("[acl_group][fromCli] Source Port Error: {} - Skipping Line".format(e))
                    # continue

                ## Destination Network
                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.destIpMask = str(address)
                except Exception as e:
                    logging.error("[acl_group][fromCli] Destination Address Error: {} - Skipping Line".format(e))
                    continue

                ### Destination Operator
                try:
                    portOperator, portStart,portStop, content = self.extractPortRange(content, newEntry.aclProtocol)
                    newEntry.destOperator = portOperator
                    newEntry.destPortStart = portStart
                    newEntry.destPortStop = portStop
                    if portStart != None or portStop != None:
                        logging.debug("[acl_group][fromCli] Destination Port Range: {} - {}".format(newEntry.destPortStart, newEntry.destPortStop))
                    else:
                        logging.debug("[acl_group][fromCli] No Destination Port Filter Detected - Ignoring")
                except Exception as e:
                    logging.debug("[acl_group][fromCli] Destination Port Not Determined - Ignoring:  Error: {}".format(e))
                    #logging.error("[acl_group][fromCli] Destination Port Error: {} - Skipping Line".format(e))
                    #continue

                ### Remaining
                newEntry.extra = content
                logging.debug("[acl_group][fromCli] Extra: {}".format(newEntry.extra))

            else:
                ## Type Not Found
                logging.error("[acl_group][fromCli] ACL Protocol Not Recognised - Skipping Line")
                continue

            ## DISPLAY Entry
            logging.info("[acl_group][fromCli] New Entry: {}".format(newEntry))

            ## Add to entries
            try:
                self.insertRow(newEntry, position)

            except Exception as e:
                logging.error("[acl_group][fromCli] Unable to add line to ACL group: {} - Skipping Line".format(e))
                continue


        ### Generate CLI
        self.toCli()

        ### Generate Hash
        self.generateHash()



        return
