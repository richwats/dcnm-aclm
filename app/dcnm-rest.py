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

import requests
from requests.auth import HTTPBasicAuth
from requests import HTTPError
import logging
logging.basicConfig(level=logging.DEBUG)

from acl import acl
import json

DCNM_FQDN = "10.67.29.26"
DCNM_TOKEN = None
DCNM_USERNAME = "apiuser"
DCNM_PASSWORD = "C!sco123"
DCNM_SESSION = None

def userLogon(expiry = 18000):
    global DCNM_SESSION
    url = "https://{}/rest{}".format(DCNM_FQDN, "/logon")
    payload = {"expirationTime": expiry}
    DCNM_SESSION = requests.Session()
    r = DCNM_SESSION.post(url, json=payload, verify=False, auth=HTTPBasicAuth(DCNM_USERNAME, DCNM_PASSWORD))
    #r.raise_for_status()
    logging.debug("Status: {}".format(r.status_code))
    logging.debug("Request URL: {}".format(r.url))
    logging.debug("Request Headers: {}".format(r.request.headers))

    if r.status_code != 200:
        ## Errorlogging.debug("Status: {}".format(r.status))
        #raise Exception("Status: {} Response: {}".format(r.status_code, r.text))
        DCNM_SESSION = None
        raise HTTPError(r.status_code, r.text, r.headers)
    else:
        # return {"Dcnm-Token": XXX }
        logging.debug("Json: {}".format(r.json()))
        global DCNM_TOKEN
        DCNM_TOKEN = r.json()['Dcnm-Token']
        if DCNM_TOKEN == None:
            raise Exception("DCNM Token not found - Exiting")
        else:
            return

def dcnmApiWrapper(method, path, payload = None):
    if DCNM_SESSION == None:
        logging.debug("No Current DCNM_SESSION Found - Logging In")
        userLogon()
    headers = {'Dcnm-Token':DCNM_TOKEN}
    ## url
    url = url = "https://{}/rest{}".format(DCNM_FQDN, path)

    if method == "get":
        r = DCNM_SESSION.get(url, verify=False, headers=headers)
    elif method == "post":
        r = DCNM_SESSION.post(url, verify=False, headers=headers, json=payload)

    ## logging
    logging.debug("Request URL: {}".format(r.url))
    logging.debug("Request Headers: {}".format(r.request.headers))
    logging.debug("Status: {}".format(r.status_code))

    if r.status_code != 200:
        ## Errorlogging.debug("Status: {}".format(r.status))
        #raise Exception("Status: {} Response: {}".format(r.status_code, r.text))
        raise HTTPError(r.status_code, r.text, r.headers)
    else:
        logging.debug("Json: {}".format(r.json()))
        return r.json()

def getDcnmFabrics():
    path = "/control/fabrics"
    output = dcnmApiWrapper("get", path)
    return output

def getSwitches(fabricName):
    path = "/control/fabrics/{}/inventory".format(str(fabricName))
    output = dcnmApiWrapper("get", path)
    return output

def getPolicyListBySwitch(serialNumber, sourceName = None):
    path = "/control/policies/switches/{}?source={}".format(serialNumber, sourceName)
    output = dcnmApiWrapper("get", path)
    logging.debug(type(output))
    if type(output) != type(list()):
        logging.debug("Converting to List")
        output = [output]
    return output

def getPolicyListBySwitches(serialNumberList, sourceName = None):
    serialNumbers = ",".join(serialNumberList)
    path = "/control/policies/switches?serialNumber={}&source={}".format(serialNumbers, sourceName)
    output = dcnmApiWrapper("get", path)
    logging.debug(type(output))
    if type(output) != type(list()):
        logging.debug("Converting to List")
        output = [output]
    return output

def processAclmPolicies(jsonList):
    """
    Iterate list of ACLM source polcies and convert to list of python objects
    """

    aclDict = {}

    for output in jsonList:
        logging.debug("Process Policy: {}".format(output))
        aclContent = output['nvPairs']['CONF']
        logging.debug("Policy Content: {}".format(aclContent))
        newAcl = acl.acl_group()
        newAcl.fromCli(aclContent)
        outputObj = json.loads(newAcl.json())
        logging.debug("JSON: {}".format(outputObj))
        logging.debug("ACL Dict: {}".format(aclDict))
        hash = outputObj['hash']
        keylist = list(aclDict.keys())
        logging.debug("Key List: {}".format(keylist))
        logging.debug("Hash: {}".format(hash))

        try:
            aclDict[hash]['policyId'][output['serialNumber']] = output['policyId']
            logging.debug("Added {} to ACL dict entry: {}".format(output['serialNumber'],aclDict))
        except KeyError:
            aclDict[hash] = {
                'name':outputObj['name'],
                #'appliedSwitches':[output['serialNumber']],
                'policyId':{output['serialNumber']:output['policyId']},
                'acl':newAcl
            }
            logging.debug("Create new ACL dict entry: {}".format(aclDict))

    return aclDict

#print(userLogon("apiuser2","C!sco123"))
#print(getDcnmFabrics())
#print(getSwitches("DC3"))
#list =(getPoliciesBySwitch("FDO22192XCF","ACLM"))
jsonList = getPolicyListBySwitches(["FDO22192XCF","FDO21521S70"],"ACLM")
processAclmPolicies(jsonList)
# assumes list?
