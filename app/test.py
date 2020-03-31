from acl import acl
import logging
logging.basicConfig(level=logging.INFO)

ag = acl.acl_group("test")
ag.fromCli("""ip access-list test
10 permit ip 10.0.0.0/8 192.168.1.0/24
20 permit tcp 3.0.0.0/8 10.0.0.0/8 eq 1500
30 remark test test test test
40 permit ip 10.0.0.0 255.0.0.0 192.168.1.0 255.255.255.0 log
50 permit ip host 1.1.1.1 host 2.2.2.2
60 permit udp host 1.1.1.1 eq 555 host 2.2.2.2 eq 555
70 permit udp 1.1.1.0 255.255.255.0 eq 555 2.1.1.0 255.255.255.0 eq 555
80 permit udp 3.1.1.0/24 range 1000 2000 2.1.1.0/24 range 2000 3000
90 deny udp 14.1.1.0 255.255.255.0 eq 555 200.1.1.0 255.255.255.0 eq 555 log
""")
test = ag.entries[10]
test.toJson()
print(ag.toJson(True))

# from acl import acl
# import logging
# logging.basicConfig(level=logging.DEBUG)
#
# ag = acl.acl_group()
# ag.fromCli("test")
