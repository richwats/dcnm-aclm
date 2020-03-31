import re
import ipaddress
import logging
import json
import hashlib

from utils import ipfunctions

class acl_entry():
    """docstring for ."""

    validTypes = ['permit', 'deny', 'remark']
    validProtocols = ['ip','tcp','udp']
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

    validFlags = ['log']
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
    aclType = None
    aclProtocol = None
    remarks = None
    sourceIpMask = None
    destIpMask = None
    sourceOperator = None
    sourcePortStart = None
    sourcePortStop = None
    destOperator = None
    destPortStart = None
    destPortStop = None
    extra = None


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
        return

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)
        #return self.__dict__

    def toJson(self):
        return json.dumps(self.__dict__,default=str)

    def json(self):
        return json.dumps(self.__dict__,default=str)

    def toDict(self):
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

        ## Source Port Range
        if self.sourcePortStart != None and self.sourcePortStop != None:
            msg = "{} {} {} range {} {}".format(self.aclType, self.aclProtocol, self.sourceIpMask, self.sourcePortStart, self.sourcePortStop )
        ## Source Port
        elif self.sourcePortStart != None and self.sourcePortStop == None:
            msg = "{} {} {} eq {}".format(self.aclType, self.aclProtocol, self.sourceIpMask, self.sourcePortStart )
        ## No Source Port
        else:
            msg = "{} {} {}".format(self.aclType, self.aclProtocol, self.sourceIpMask)

        logging.debug(msg)
        ## Destination Port Range
        if self.destPortStart != None and self.destPortStop != None:
            msg = msg + " {} range {} {}".format(self.destIpMask, self.destPortStart, self.destPortStop)
        ## Destination Port
        elif self.destPortStart != None and self.destPortStop == None:
            msg = msg + " {} eq {}".format(self.destIpMask, self.destPortStart)
        ## No Destination Port
        else:
            msg = msg + " {}".format(self.destIpMask)

        ## Log
        if "log" in self.extra:
            msg = msg + " {}".format("log")

        logging.debug(msg)
        return msg


class acl_group():
    """docstring for ."""

    name = ""
    interval = 10
    entries = {}
    hash = None

    def __init__(self, name = None):
        self.name = name

    def getLastEntry(self):
        keylist = list(self.entries.keys())
        if len(keylist) > 0:
            return max(keylist)
        else:
            return 0

    def insertRow(self, row, position ):
        if position == 0:
            position = self.getLastEntry() + self.interval
        self.entries[position] = row
        self.generateHash()
        return

    def removeRow(self, position):
        row = self.entries.pop(position, None)
        self.generateHash()
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
            logging.debug(address)

        elif content[0] == "any":
            address = ipaddress.IPv4Network('0.0.0.0/0')
            content = content[1:]
            logging.debug(address)

        ## Network Subnet Detection
        elif ipfunctions.isIpV4Adddress(content[0]) and ipfunctions.isSubnetMask(content[1]):
            logging.debug("Address in Network|Mask Notation")
            address = ipaddress.IPv4Network((content[0],content[1]))
            content = content[2:]
            logging.debug(address)

        ## Network/MaskLen Detection
        elif ipfunctions.isIpV4AdddressMask(content[0]):
            logging.debug("Address in Network/Length Notation")
            address = ipaddress.IPv4Network(content[0])
            content = content[1:]
            logging.debug(address)

        else:
            raise Exception('Address Not Determined')

        return address,content

    def extractPortRange(self, content):
        # Get list of valid operators
        validOperators = acl_entry.validOperators

        if content[0] in validOperators:
            logging.debug("Port Operator: {}".format(content[0]))
            portOperator = content[0]

            ## Port Range?
            if portOperator == "range":
                ## Check Valid Port
                if int(content[1]) <= 65535 and int(content[2]) <= 65535:
                    portStart = content[1]
                    portStop = content[2]
                    content = content[3:]
                    logging.debug("Port Range: {} - {}".format(portStart, portStop))
                else:
                    raise Exception('Port Out of Valid Range')

            else:
                ## Check Valid Port
                if int(content[1]) <= 65535:
                    portStart = content[1]
                    portStop = None
                    content = content[2:]
                    logging.debug("Source Port: {}".format(portStart))
                else:
                    raise Exception("Port Out of Valid Range")

            return portStart, portStop, content

        else:
            logging.debug("No Port Filter Detected")
            return None, None, content

    def toCli(self):
        output = "ip access-list {}\n".format(self.name)
        sorted(self.entries)
        for k,v in self.entries.items():
            output = output + "  {} {}\n".format(k, v.toCli())
        return output

    def toJson(self, pretty = False):
        sorted(self.entries)
        jsonDict = {}
        jsonDict['name'] = self.name
        jsonDict['hash'] = self.hash
        jsonDict['entries'] = {}
        for k,v in self.entries.items():
            jsonDict['entries'][k] = v.toDict()
        #logging.debug(jsonDict)
        #logging.info(json.dumps(jsonDict))
        if pretty:
            return json.dumps(jsonDict, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(jsonDict)

    def json(self, pretty = False):
        return self.toJson(pretty)

    def generateHash(self):
        logging.debug("Generating MD5 hash of CLI content")
        content = str(self.toCli())
        logging.debug("Content: {}".format(content))
        content = content.encode('utf-8')
        self.hash = hashlib.md5(content).hexdigest()
        logging.debug("Hash: {}".format(self.hash))
        return

    def fromCli(self, input):
        """
        Take full ACL and parse to objects

        """
        ### Clear entries
        self.entries = {}

        ### Parse Lines
        lines = input.splitlines()

        ## Extract Name
        p = re.compile('^ip access-list ([\w]+)$')
        m = p.match(lines[0])
        if m != None and m.group(1):
            logging.info("ACL Name: {}".format(m.group(1)))
            self.name = str(m.group(1))
            ## Generate hash
            self.generateHash()
        else:
            ## Error
            logging.error('Unable to extract IP ACL name')
            raise Exception('Unable to extract IP ACL name')
            #return

        ## Iterate lines
        for line in lines[1:]:
            newEntry = acl_entry()
            line = line.strip()
            logging.info("Processing Line: {}".format(line))
            ##
            words = line.split(" ")
            logging.debug(words)

            ## Determine Entry Number
            p = re.compile('^[0-9]+')
            m = p.match(words[0])
            if m != None and m.group(0):
                 position = int(m.group(0))
                 logging.debug("ACL Entry: {}".format(m.group(0)))
            else:
                ##Error
                # No Number
                #raise Error('Unable to extract ACL entry number')
                logging.error('Unable to extract ACL entry number - Skipping line')
                continue

            ## Determine Type
            if words[1] in newEntry.validTypes:
                newEntry.aclType = words[1]
                logging.debug("ACL Type: {}".format(words[1]))
            else:
                logging.error('Unable to determine ACL entry type - Skipping line')
                continue

            ## Check for remark
            if newEntry.aclType == "remark":
                newEntry.remarks = str(" ").join(words[2:])
                logging.debug("ACL Remark: {}".format(newEntry.remarks))
                try:
                    self.insertRow(newEntry, position)
                except Exception as e:
                    logging.error("Unable to add remark to ACL group: {} - Skipping Line".format(e))
                    continue


            ## Determine Protocol
            if words[2] in newEntry.validProtocols:
                newEntry.aclProtocol = words[2]
                #print("ACL Protocol: {}".format(newEntry.aclProtocol))
                content = words[3:]
            else:
                ## No Protocol Detected
                ## Error
                logging.error('Unable to determine ACL entry protocol - Skipping line')
                continue

            ## "ip" entry handling
            if newEntry.aclProtocol == "ip":

                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.sourceIpMask = str(address)
                except Exception as e:
                    logging.error("Source Address Error: {} - Skipping Line".format(e))
                    continue

                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.destIpMask = str(address)
                except Exception as e:
                    logging.error("Destination Address Error: {} - Skipping Line".format(e))
                    continue

                ### Remaining
                newEntry.extra = content
                logging.debug("Extra: {}".format(newEntry.extra))


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
                    logging.error("Source Address Error: {} - Skipping Line".format(e))
                    continue

                ### Source Operator

                try:
                    portStart,portStop, content = self.extractPortRange(content)
                    newEntry.sourcePortStart = portStart
                    newEntry.sourcePortStop = portStop
                    if portStart != None or portStop != None:
                        logging.debug("Source Port Range: {} - {}".format(newEntry.sourcePortStart, newEntry.sourcePortStop))
                    else:
                        logging.debug("No Source Port Filter Detected - Ignoring")
                except Exception as e:
                    logging.error("Source Port Error: {} - Skipping Line".format(e))
                    continue

                ## Destination Network
                try:
                    address, content = self.extractIPv4NetMask(content)
                    newEntry.destIpMask = str(address)
                except Exception as e:
                    logging.error("Destination Address Error: {} - Skipping Line".format(e))
                    continue

                ### Destination Operator
                try:
                    portStart,portStop, content = self.extractPortRange(content)
                    newEntry.destPortStart = portStart
                    newEntry.destPortStop = portStop
                    if portStart != None or portStop != None:
                        logging.debug("Destination Port Range: {} - {}".format(newEntry.destPortStart, newEntry.destPortStop))
                    else:
                        logging.debug("No Destination Port Filter Detected - Ignoring")
                except Exception as e:
                    logging.error("Destination Port Error: {} - Skipping Line".format(e))
                    continue

                ### Remaining
                newEntry.extra = content
                logging.debug("Extra: {}".format(newEntry.extra))

            else:
                ## Type Not Found
                logging.error("ACL Protocol Not Recognised - Skipping Line")
                continue

            ## DISPLAY Entry
            logging.info(newEntry)

            ## Add to entries
            try:
                self.insertRow(newEntry, position)
            except Exception as e:
                logging.error("Unable to add line to ACL group: {} - Skipping Line".format(e))
                continue

        return
