## TEST REST API PUSH

"""
- Login to API
    - Use Daemon normally?
    - Temp user login for testing?
- Get Fabrics
- Get Switches
- Get Policies by Source - "ACLM"
- CONFIRM SAME CONTENT
- Convert to Python objects

- Render in flask/HTML
- Edit in flask/HTML
    - Datatables?

- Convert to CLI
- Create/Update Policies
- Deploy Policies

"""

import logging
logging.basicConfig(level=logging.DEBUG)
from aclm import aclm
from datetime import datetime

#print(userLogon("apiuser2","C!sco123"))
#print(getDcnmFabrics())
#print(getSwitches("DC3"))
#list =(getPoliciesBySwitch("FDO22192XCF","ACLM"))

## Build Managed ACL Object
testACLM = aclm()

## Load ACLM Policies from Switches by Serial Number
jsonList = testACLM.getPolicyListBySwitches(["FDO22192XCF","FDO21521S70"])
testACLM.processPolicies(jsonList)

## Get First Managed ACL Policy ##
keylist = list(testACLM.ACLS.keys())
firstACL = testACLM.ACLS[keylist[0]]
# print(firstACL.acl)
# print(dir(firstACL.acl))

## Modify Row 20
modifyRow = firstACL.acl.getRow(20)
modifyRow.remarks = "update test time:{}".format(datetime.now())
firstACL.acl.generateHash()

# ## Add New Row to Managed ACL ##
# newRow = firstACL.acl.getNewAclObject()
# newRow.aclType = "remark"
# newRow.remarks = "TEST REMARK ABC123"
# firstACL.acl.insertRow(newRow)

# # ## Remove Row from Managed ACL ##
# firstACL.acl.removeRow(40)

#firstACL.markDetachACLfromSwitch("FDO21521S70")
#firstACL.markAttachACLtoSwitch("FDO21521S70")

#print(firstACL)

testACLM.updatePolicies(firstACL)
testACLM.deployPolicies(firstACL)
#print(firstACL.toDeploy)

## Update Managed ACL Policies
