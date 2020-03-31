## IP Address Functions

import re
import ipaddress

def isIpV4Adddress(input):
    # Check for network mask notation
    p = re.compile('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    m = p.match(input)

    #print(m)

    if m !=None:
        return True
    else:
        return False

def isSubnetMask(input):
    # Check for network mask notation
    # p1 = re.compile('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    # m1 = p1.match(words[3])
    p = re.compile('^(?:(255|254|252|248|240|224|192|128|0)[.]){3}(255|254|252|248|240|224|192|128|0)$')
    m = p.match(input)

    #print(m)

    if m !=None:
        return True
    else:
        return False

def isIpV4AdddressMask(input):
    # Check for network mask notation
    p = re.compile('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]{1,2})$')
    m = p.match(input)

    #print(m)

    if m !=None:
        return True
    else:
        return False
