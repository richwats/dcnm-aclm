import logging
import requests
import json
from datetime import datetime
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from requests import HTTPError

"""
Expected workflow
- Select Fabric(s)
    - Scope in ACLM
    - List of Serial Numbers ("SELECTED_SERIAL_NUMBERS")
- Discover existing managed ACLS
    (/selectSwitches)
- Modify existing ACL
    - Rename
    - Add Switch(es)
    - Remove Switch(es)
        - Remove from all? == Delete ACL?
    - Modify ACL Content
- Add new ACL
- Delete ACL
    - If Deployed
        - Delete Policy & Deploy
    - If Pending
        - Delete Policy
    - If New
        - Clear from cache
"""

from acl import acl


class managedACL():
    """
    Managed ACL Object
    - Hash
    - Name
    - Serial Number:Policy-ID Dictionary
    - ACL Object

    """
    # name = None
    # hash = None
    #
    # # Status
    # status = None  # New, Deployed
    # # NotApplied - No switches applied
    # # Applied - Policy IDs exist for one or more switches
    #
    # policies = dict() # Deployed Policies
    # acl = None
    # toAttach = set()
    # toDetach = set()
    # toDeploy = set() #list of Policy-IDs to deploy

    def __init__(self, name, hash, serialNumber, policyId, aclObject):

        ## Needs to be reset first!!!
        self.name = None
        self.hash = None
        self.status = None  # New, Deployed
        self.policies = dict() # Deployed Policies
        self.acl = None
        self.toAttach = set()
        self.toDetach = set()
        self.toDeploy = set()

        logging.debug("[managedACL][__init__] {} {} {} {} {}".format(name, hash, serialNumber, policyId, aclObject))
        logging.debug("[managedACL][__init__] Before Policies: {}".format(self.policies))
        self.name = name
        self.hash = hash
        if serialNumber != None:
            self.policies[serialNumber] = policyId
            logging.debug("[managedACL][__init__] Add Policy: {} to Policy Dict: {}".format(policyId, self.policies))
        else:
            self.policies = dict()
            logging.debug("[managedACL][__init__] Reset Policies: {}".format(self.policies))
        self.acl = aclObject

        if serialNumber != None and policyId != None:
            self.status = "Applied"
        else:
            self.status = "NotApplied"

        logging.debug("[managedACL][__init__] After Policies: {}".format(self.policies))
        return

    def appendSwitch(self, serialNumber, policyId):
        """
        Add switches with same Managed ACL policy content to object
        - Does NOT create or update policies
        """
        self.policies[serialNumber] = policyId
        self.status = "Applied"
        return

    def __str__(self):
        return str({
        'name': self.name,
        'hash': self.hash,
        'status': self.status,
        'policies': self.policies,
        'acl': str(self.acl),
        'toAttach': str(self.toAttach),
        'toDetach': str(self.toDetach),
        'toDeploy': str(self.toDetach)
        })

    def markAttachACLtoSwitch(self, serialNumber):
        if serialNumber not in list(self.policies.keys()):
            self.toAttach.add(serialNumber)
            self.toDetach.discard(serialNumber)
            logging.info("[managedACL][markAttachACLtoSwitch] Attached ACL to Serial Number: {}".format(serialNumber))
            return
        else:
            raise Exception("ACL already attached to serial number: {}".format(serialNumber))

    def markDetachACLfromSwitch(self, serialNumber):
        if serialNumber in list(self.policies.keys()):
            self.toDetach.add(serialNumber)
            self.toAttach.discard(serialNumber)
            logging.info("[managedACL][markDetachACLfromSwitch] Detached ACL from Serial Number: {}".format(serialNumber))
            return
        else:
            raise Exception("ACL already detached from serial number: {}".format(serialNumber))

    def toJson(self):
        output = self.toDict()
        jsonOutput = json.dumps(output)
        logging.debug("[managedACL][toJson] JSON: {}".format(jsonOutput))
        return json.dumps(jsonOutput)

    def toDict(self):
        """
        Convert to Python Dict
        """
        output = {
        "name": self.name,
        "hash": self.hash,
        "status": self.status,
        "policies": self.policies,
        "acl": self.acl.toDict(),
        #"cli": self.acl.toCli(),
        "cli": self.acl.cli,
        "toAttach": list(self.toAttach),
        "toDetach": list(self.toDetach),
        "toDeploy": list(self.toDeploy)
        }
        logging.debug("[managedACL][toDict] Managed ACL Dict: {}".format(output))
        return output

    def updateFromJson(self, jsonInput):
        """
        Update Managed ACL from JSON Input
        - name
        - acl
        - toAttach
        - toDetach

        ..everything else ignored
        """
        logging.debug("[managedACL][updateFromJson] Updating Managed ACL from Json: {}".format(jsonInput))

        ## Change Name
        if 'name' in list(jsonInput.keys()):
            if jsonInput['name'] != self.name:
                self.acl.name = jsonInput['name']
                self.acl.generateHash()
                self.name = jsonInput['name']

        ## Attach New Switch
        if len(jsonInput['toAttach']) > 0:
            for serial in jsonInput['toAttach']:
                self.markAttachACLtoSwitch(serial)

        ## Detach Switch
        if len(jsonInput['toDetach']) > 0:
            for serial in jsonInput['toDetach']:
                self.markDetachACLfromSwitch(serial)

        ## Update ACL
        self.acl.fromJson(jsonInput['acl'])

        return self.toDict()

    def updateFromCli(self, jsonInput):
        """
        Update Managed ACL from CLI Input in JSON payload
        - name
        - cli
        - toAttach
        - toDetach

        ..everything else ignored
        """
        logging.debug("[managedACL][updateFromCli] Updating Managed ACL from CLI: {}".format(jsonInput['cli']))

        ## Change Name
        if 'name' in list(jsonInput.keys()):
            if jsonInput['name'] != self.name:
                self.acl.name = jsonInput['name']
                self.acl.generateHash()
                self.name = jsonInput['name']

        ## Attach New Switch
        if len(jsonInput['toAttach']) > 0:
            for serial in jsonInput['toAttach']:
                self.markAttachACLtoSwitch(serial)

        ## Detach Switch
        if len(jsonInput['toDetach']) > 0:
            for serial in jsonInput['toDetach']:
                self.markDetachACLfromSwitch(serial)

        ## Update ACL
        self.acl.fromCli(jsonInput['cli'])

        return self.toDict()

class aclm():
    """
    DCNM ACL Manager Class

    Functions:
    - userLogon
    - dcnmApiWrapper
    - getFabrics
    - getFabricInventory
    - getPolicyById
    - getPolicyListBySwitch
    - getPolicyListBySwitches
    - processPolicies
    - updatePolicies
    - deployPolicies
    """
    # DCNM_FQDN = None
    # DCNM_TOKEN = None
    # DCNM_USERNAME = None
    # DCNM_PASSWORD = None
    # DCNM_SESSION = None
    # DCNM_EXPIRY = None
    #
    # DCNM_SOURCE = "ACLM"
    #
    # ### ACL Group Objects as dictionary by hash
    # ACLS = {}
    #
    # #SELECTED_SERIAL_NUMBERS = None
    # SELECTED_FABRIC = None
    # POLICY_CACHE = {}
    # FABRIC_INVENTORY = None
    # ACLM_OBJECTS = {}

    def __init__(self, *args, **kwargs):
        # DCNM_FQDN, DCNM_USERNAME, DCNM_PASSWORD
        # DCNM_FQDN = "10.67.29.26", DCNM_USERNAME = "apiuser", DCNM_PASSWORD = "C!sco123"
        logging.info("[aclm][__init__] Initialising ACLM Object")
        #logging.debug(args)
        #logging.debug(kwargs)

        ## Reset
        self.DCNM_FQDN = None
        self.DCNM_TOKEN = None
        self.DCNM_USERNAME = None
        self.DCNM_PASSWORD = None
        self.DCNM_OFFLOADED = None
        self.DCNM_SESSION = None
        self.DCNM_EXPIRY = None
        self.DCNM_SOURCE = "ACLM"
        self.ACLS = {}
        self.SELECTED_FABRIC = None
        self.POLICY_CACHE = {}
        self.FABRIC_INVENTORY = None
        self.ACLM_OBJECTS = {}


        try:
            logging.debug("[aclm][__init__]DCNM_FQDN: {}".format(kwargs['DCNM_FQDN']))
            #logging.debug("[aclm][__init__]DCNM_USERNAME: {}".format(kwargs['DCNM_USERNAME']))
            #logging.debug("[aclm][__init__]DCNM_PASSWORD: {}".format(kwargs['DCNM_PASSWORD']))
            self.DCNM_FQDN = kwargs['DCNM_FQDN']
            self.DCNM_USERNAME = kwargs['DCNM_USERNAME']
            self.DCNM_PASSWORD = kwargs['DCNM_PASSWORD']
            self.DCNM_OFFLOADED = kwargs['DCNM_OFFLOADED']

        except:
            raise Exception("No DCNM Credentials Provided")

        if 'DCNM_TOKEN' in list(kwargs.keys()):
            logging.info("[aclm][__init__] Additional Session Information Found - Rebuilding")
            self.DCNM_TOKEN = kwargs['DCNM_TOKEN']
            if not self.DCNM_OFFLOADED:
                ## If offloaded, don't look for DCNM_EXPIRY
                self.DCNM_EXPIRY = kwargs['DCNM_EXPIRY']
            else:
                self.DCNM_EXPIRY = None

            updateCache = False
            if kwargs.get('UPDATE_CACHE') == True:
                logging.debug("[aclm][__init__] Force Update Policy Cache")
                updateCache = True

            if kwargs.get('SELECTED_FABRIC') != None:
                self.SELECTED_FABRIC = kwargs.get('SELECTED_FABRIC')
                inventoryList = self.getFabricInventory(self.SELECTED_FABRIC)
                fabric_inventory = self.processInventory(inventoryList)
                self.FABRIC_INVENTORY = fabric_inventory
                serialNumberList = list(self.FABRIC_INVENTORY.keys())

                if len(serialNumberList) == 0:
                    logging.debug("[aclm][__init__] Selectd Fabric has no devices - Not Building Policies")
                    return

                ## Set ACLM Objects from Session
                self.ACLM_OBJECTS = kwargs.get('ACLM_OBJECTS')

                ### Fabric Selected, build policies
                if updateCache == True:
                    ## Update Policy Cache
                    logging.debug("[aclm][__init__] Updating Cache - Building Policies from Updated Switch List")
                    jsonList = self.getPolicyListBySwitches(serialNumberList)
                    self.processPolicies(jsonList)
                    for entry in jsonList:
                        self.POLICY_CACHE[entry['policyId']] = entry
                    # self.POLICY_CACHE = jsonList
                    return
                elif kwargs.get('POLICY_CACHE') == None:
                    ## Build New Policy Cache
                    logging.debug("[aclm][__init__] No Policy Cache - Building Policies from Updated Switch List")
                    jsonList = self.getPolicyListBySwitches(serialNumberList)
                    self.processPolicies(jsonList)
                    for entry in jsonList:
                        self.POLICY_CACHE[entry['policyId']] = entry
                    return
                else:
                    ## Build from Policy Cache
                    logging.debug("[aclm][__init__] Building Policies from Cache")
                    self.POLICY_CACHE = kwargs['POLICY_CACHE']
                    jsonList = []
                    for policyId, entry in self.POLICY_CACHE.items():
                        jsonList.append(entry)
                    self.processPolicies(jsonList)
                    return

            else:
                logging.debug("[aclm][__init__] No Selected Fabric - Not Building Policies")
                return

        else:
            logging.warning("[aclm][__init__] No DCNM_TOKEN - Not Logged In")
            return


    def setupRequestsSession(self):
        """
        Define DCNM_SESSION requests session object
        """
        self.DCNM_SESSION = requests.Session()

        ## Allow for HTTP Retries
        adapt = requests.adapters.HTTPAdapter(max_retries=5)
        self.DCNM_SESSION.mount('https://', adapt)

        return


    def dcnmLogon(self, expiry = 180000):
        """
        Builds DCNM_TOKEN from /logon
        """
        url = "https://{}/rest{}".format(self.DCNM_FQDN, "/logon")
        payload = {"expirationTime": expiry}

        self.setupRequestsSession()

        # self.DCNM_SESSION = requests.Session()
        #
        # ## Allow for HTTP Retries
        # # a = requests.adapters.HTTPAdapter(max_retries=3)
        # adapt = requests.adapters.HTTPAdapter(max_retries=5)
        # # self.DCNM_SESSION.mount('http://', a)
        # self.DCNM_SESSION.mount('https://', adapt)

        logging.debug("[aclm][userLogon] Datetime: {}".format(datetime.now()))
        self.DCNM_EXPIRY = datetime.now().timestamp() + (int(expiry) / 1000)

        r = self.DCNM_SESSION.post(url, json=payload, verify=False, auth=HTTPBasicAuth(self.DCNM_USERNAME, self.DCNM_PASSWORD))
        #r.raise_for_status()
        logging.info("[aclm][userLogon] DCNM Token Expiry: {}".format(self.DCNM_EXPIRY))
        logging.debug("[aclm][userLogon] Status: {}".format(r.status_code))
        logging.debug("[aclm][userLogon] Request URL: {}".format(r.url))
        logging.debug("[aclm][userLogon] Request Headers: {}".format(r.request.headers))

        if r.status_code != 200:
            ## Errorlogging.debug("Status: {}".format(r.status))
            #raise Exception("Status: {} Response: {}".format(r.status_code, r.text))
            self.DCNM_SESSION = None
            raise HTTPError(r.status_code, r.text, r.headers)
        else:
            # return {"Dcnm-Token": XXX }
            logging.debug("[aclm][userLogon] Json: {}".format(r.json()))
            self.DCNM_TOKEN = r.json()['Dcnm-Token']
            if self.DCNM_TOKEN == None:
                raise Exception("DCNM Token not found - Exiting")
            else:
                return

    def dcnmLogout(self):
        """
        Logs out from /logout
        """
        path = "/logout"
        output = self.dcnmApiWrapper("post", path)
        return output

    def dcnmApiWrapper(self, method, path, payload = None):

        logging.debug("[aclm][dcnmApiWrapper] Token Expiry: {}".format(self.DCNM_EXPIRY))
        logging.debug("[aclm][dcnmApiWrapper] Time Now: {}".format(datetime.now().timestamp()))

        if self.DCNM_TOKEN == None:
            logging.debug("[aclm][dcnmApiWrapper] No Current DCNM Token Found - Logging In")
            self.dcnmLogon()
        elif self.DCNM_EXPIRY != None and datetime.now().timestamp() > self.DCNM_EXPIRY:
            ## Renew token
            logging.debug("[aclm][dcnmApiWrapper] Current DCNM Token Expired - Logging In")
            self.dcnmLogon()
        elif self.DCNM_SESSION == None:
            logging.debug("[aclm][dcnmApiWrapper] No Current DCNM Session Found - Starting New Session")
            self.setupRequestsSession()
            # self.DCNM_SESSION = requests.Session()

        headers = {'Dcnm-Token':self.DCNM_TOKEN}
        ## url
        url = url = "https://{}/rest{}".format(self.DCNM_FQDN, path)

        if method == "get":
            r = self.DCNM_SESSION.get(url, verify=False, headers=headers)
        elif method == "delete":
            r = self.DCNM_SESSION.delete(url, verify=False, headers=headers)
        elif method == "post":
            r = self.DCNM_SESSION.post(url, verify=False, headers=headers, json=payload)
        elif method == "put":
            r = self.DCNM_SESSION.put(url, verify=False, headers=headers, json=payload)
        else:
            raise Exception("Unknown HTTP Method")

        ## logging
        logging.debug("[aclm][dcnmApiWrapper] Request URL: {}".format(r.url))
        logging.debug("[aclm][dcnmApiWrapper] Request Headers: {}".format(r.request.headers))
        logging.debug("[aclm][dcnmApiWrapper] Status: {}".format(r.status_code))


        if r.status_code == 401:
            ## Relogin?
            ## Should never trigger from Offloaded Frontend!
            self.dcnmLogon()
            return self.dcnmApiWrapper(method, path, payload)

        elif r.status_code not in [200, 202]:
            ## Errorlogging.debug("Status: {}".format(r.status))
            #raise Exception("Status: {} Response: {}".format(r.status_code, r.text))
            raise HTTPError(r.status_code, r.text, r.headers)

        else:
            try:
                ## Check for json output
                logging.debug("[aclm][dcnmApiWrapper] Json: {}".format(r.json()))
                return r.json()
            except:
                logging.debug("[aclm][dcnmApiWrapper] Text: {}".format(r.text))
                return True

    def getFabrics(self):
        path = "/control/fabrics"
        output = self.dcnmApiWrapper("get", path)
        return output

    def getFabricInventory(self, fabricName):
        path = "/control/fabrics/{}/inventory".format(str(fabricName))
        output = self.dcnmApiWrapper("get", path)
        return output

    def processInventory(self, inventoryList):
        output = {}
        for device in inventoryList:
            output[device['serialNumber']] = {
                'serialNumber': device['serialNumber'],
                'displayName': device['logicalName'],
                'fabricName': device['fabricName'],
                'release': device['release'],
                'model': device['model'],
                'switchRole': device['switchRole']
            }
        return output

    def getPolicyById(self, policyId):
        path = "/control/policies/{}".format(policyId)
        output = self.dcnmApiWrapper("get", path)
        return output

    def getPolicyListBySwitch(self, serialNumber, sourceName = None):
        path = "/control/policies/switches/{}?source={}".format(serialNumber, sourceName)
        output = self.dcnmApiWrapper("get", path)
        #logging.debug(type(output))
        if type(output) != type(list()):
            logging.debug("[aclm][getPolicyListBySwitch] Converting to List")
            output = [output]
        return output

    def getPolicyListBySwitches(self, serialNumberList):
        serialNumbers = ",".join(serialNumberList)
        path = "/control/policies/switches?serialNumber={}&source={}".format(serialNumbers, self.DCNM_SOURCE)
        output = self.dcnmApiWrapper("get", path)
        #logging.debug(type(output))
        if type(output) != type(list()):
            logging.debug("Converting to List")
            output = [output]
        return output

    # def getPolicyListByFabric(self, fabricName):
    #     ## Can be improved - cached?
    #     inventoryList = self.getFabricInventory(fabricName)
    #     fabric_inventory = self.processInventory(inventoryList)
    #     serialNumberList = list(fabric_inventory.keys())
    #     serialNumbers = ",".join(serialNumberList)
    #     path = "/control/policies/switches?serialNumber={}&source={}".format(serialNumbers, self.DCNM_SOURCE)
    #     output = self.dcnmApiWrapper("get", path)
    #     if type(output) != type(list()):
    #         logging.debug("Converting to List")
    #         output = [output]
    #     return output

    def putUpdatedPolicyById(self, policyId, payload):
        path = "/control/policies/{}".format(policyId)
        output = self.dcnmApiWrapper("put", path, payload)
        return output

    def buildPolicyPayload(self, serialNumber, content, priority = 500):
        """
        {
          "description": "REST API TEST POLICY",
          "serialNumber": "FDO21521S70",
          "entityType": "SWITCH",
          "entityName": "SWITCH",
          "templateName": "switch_freeform",
          "templateContentType": "PYTHON",
          "nvPairs": {
            "CONF": "ip access-list TEST2\n  10 permit ip any any"
          },
          "source": "ACLM",
          "priority": 500
        }
        """
        #logging.debug("[aclm][buildPolicyPayload] DCNM_SOURCE: {}".format(self.DCNM_SOURCE))
        payload = {}
        payload['description'] = "REST API TEST POLICY"
        payload['serialNumber'] = serialNumber
        payload['entityType'] = "SWITCH"
        payload['entityName'] = "SWITCH"
        payload['templateName'] = "switch_freeform"
        payload['templateContentType'] = "PYTHON"
        payload['nvPairs'] = {}
        payload['nvPairs']['CONF'] = content
        payload['source'] = self.DCNM_SOURCE
        payload['priority'] = priority

        return payload

    def postNewPolicy(self, payload):
        path = "/control/policies"
        output = self.dcnmApiWrapper("post", path, payload)
        return output

    def postDeployPolicyList(self, payload):
        path = "/control/policies/deploy"
        output = self.dcnmApiWrapper("post", path, payload)
        return output

    def postDeployFabricSwitch(self, serialNumber):
        path = "/control/fabrics/{}/config-deploy/{}".format(self.SELECTED_FABRIC, serialNumber)
        output = self.dcnmApiWrapper("post", path, None)
        return output

    def deletePolicyById(self, policyId):
        path = "/control/policies/{}".format(policyId)
        output = self.dcnmApiWrapper("delete", path)
        return output

    def putMarkPolicyDeleteById(self, policyId):
        path = "/control/policies/{}/mark-delete".format(policyId)
        output = self.dcnmApiWrapper("put", path)
        return output

    def processPolicies(self, jsonList):
        """
        Iterate list of ACLM source polcies and convert to list of ACL python objects
        """

        ## Reset ACL Dictionary
        self.ACLS = {}

        for output in jsonList:
            logging.debug("[aclm][processPolicies] Process Policy: {}".format(output))
            aclContent = output['nvPairs']['CONF']
            logging.debug("[aclm][processPolicies] Policy Content: {}".format(aclContent))

            newAcl = acl.acl_group()

            ## Build ACL Content from Policy CLI
            newAcl.fromCli(aclContent)

            #outputObj = json.loads(newAcl.json())

            logging.debug("[aclm][processPolicies] JSON: {}".format(newAcl.toDict()))
            #logging.debug("ACL Dict: {}".format(self.ACLS))

            #hash = outputObj['hash']
            newName = newAcl.name
            newHash = newAcl.hash

            keylist = list(self.ACLS.keys())
            logging.debug("[aclm][processPolicies] Key List: {}".format(keylist))
            logging.debug("[aclm][processPolicies] ACL Hash: {}".format(newHash))

            try:
                existingInst = self.ACLS[newHash]
                logging.debug("[aclm][processPolicies] Existing Policies: {}".format(existingInst.policies))
                existingInst.appendSwitch(output['serialNumber'], output['policyId'])
                logging.info("[aclm][processPolicies] Policy: {} - Added {} to Managed ACL Object: Hash: {}".format(output['policyId'], output['serialNumber'], newHash))
                logging.debug("[aclm][processPolicies] Updated Policies: {}".format(existingInst.policies))

            except KeyError:
                ## Not instaniating new .policies dict !!!

                newAclInst = managedACL(newName, newHash, output['serialNumber'], output['policyId'], newAcl)
                # logging.debug("[aclm][processPolicies] New Managed ACL Object Policies: {}".format(newAclInst.policies))
                self.ACLS[newHash] = newAclInst
                logging.info("[aclm][processPolicies] Created new Managed ACL Object from Policy {}. Hash: {}".format(output['policyId'], newHash))
                # logging.debug("[aclm][processPolicies] After ACLS Policies: {}".format(self.ACLS[newHash].policies))

        ## Update toDeploy list
        self.updateDeployList()

        return

    def updateDeployList(self):
        ## Check ACLM Session to set toDeploy
        logging.debug("[aclm][updateDeployList] Updating toDeploy from session objects")
        logging.debug("[aclm][updateDeployList] ACLM_OBJECTS: {}".format(self.ACLM_OBJECTS))
        logging.debug("[aclm][updateDeployList] ACLS: {}".format(self.ACLS))

        """
        Hash changes!
        """

        for hash, sessionDict in self.ACLM_OBJECTS.items():
            if hash in list(self.ACLS.keys()):
                ## Update toDeploy
                logging.debug("[aclm][updateDeployList] Hash: {}".format(hash))
                self.ACLS[hash].toDeploy = set(sessionDict['toDeploy'])
                logging.debug("[aclm][updateDeployList] toDeploy: {}".format(self.ACLS[hash].toDeploy))
            else:
                logging.debug("[aclm][updateDeployList] Hash {} not in ACLS".format(hash))
        return

    def updatePolicies(self, managedACL ):
        """
        Update all policies with new content
        - Check if hash has changed?
        - if so, update, if not skip
        - Does NOT deploy policies!
        """

        ## Check toAttach
        if len(managedACL.toAttach) > 0:
            logging.debug("[aclm][updatePolicies] Attaching ACL to new switch(es)")
            deltaToAttach = set()
            for serialNumber in managedACL.toAttach:
                ## Add New Policy
                #payload = self.buildPolicyPayload(serialNumber, managedACL.acl.toCli())
                payload = self.buildPolicyPayload(serialNumber, managedACL.acl.cli)
                output = self.postNewPolicy(payload)
                logging.debug("[aclm][updatePolicies] New Policy Response: {}".format(output))
                policyId = output['policyId']
                logging.info("[aclm][updatePolicies] Policy - {} - Added to Serial Number: {}".format(policyId, serialNumber))

                ## Add to managedACL policy dict.
                managedACL.policies[serialNumber] = policyId

                ## Mark Policy for Deployment
                logging.debug("[aclm][updatePolicies] Adding {} to toDeploy".format(policyId))
                managedACL.toDeploy.add(policyId)

                ## Remove for toAttach set
                deltaToAttach.add(serialNumber)

            ## Update toAttach
            managedACL.toAttach.difference_update(deltaToAttach)
            managedACL.status = "Applied"

        else:
            logging.info("[aclm][updatePolicies] No new switches attached to ACL")

        ## Check toDetach
        if len(managedACL.toDetach) > 0:
            logging.debug("[aclm][updatePolicies] Detaching ACL from switch(es)")
            deltaToDetach = set()
            for serialNumber in managedACL.toDetach:
                ## Get Policy
                logging.debug("[aclm][updatePolicies] Serial Number: {}".format(serialNumber))
                policyId = managedACL.policies[serialNumber]

                ## Delete Policy
                output = self.deletePolicyById(policyId)
                logging.info("[aclm][updatePolicies] Policy - {} - Deleted from Serial Number: {}".format(policyId, serialNumber))

                # ## Mark Policy for Delete
                # Don't like..
                # output = self.putMarkPolicyDeleteById(policyId)

                # ## Mark Policy for Deployment
                # logging.debug("[aclm][updatePolicies] Adding {} to toDeploy".format(policyId))
                # managedACL.toDeploy.add(policyId)

                ## Remove from managedACL policy dict.
                managedACL.policies.pop(serialNumber)

                ## Remove for toDetach set
                deltaToDetach.add(serialNumber)

            ## Update toDetach
            managedACL.toDetach.difference_update(deltaToDetach)

        else:
            logging.info("[aclm][updatePolicies] No switches detached from ACL")

        # ## Check if empty!
        # if len(managedACL.policies) == 0:
        #     logging.warning("[aclm][updatePolicies] No switches attached to ACL.  This ACL will be moved to pending")
        #     # logging.debug("[aclm][updatePolicies] ACL: {}".format(managedACL.acl.cli))
        #     managedACL.status = "NotApplied"
        #     # session['PENDING'][managedACL.hash] = managedACL

        ## Check Content Hash
        if managedACL.acl.hash != managedACL.hash:
            logging.info("[aclm][updatePolicies] ACL content has changed.  Updating associated policies.")
            ## Content has changed - Push update

            ## Iterate Existing Switch Policies
            for serialNumber, policyId in managedACL.policies.items():
                ## Get Policy
                logging.debug("[aclm][updatePolicies] Serial Number: {}".format(serialNumber))


                policy = self.POLICY_CACHE[policyId]
                # policy = self.getPolicyById(policyId)


                logging.debug("[aclm][updatePolicies] Existing Policy: {}".format(policy))
                #updatedCli = managedACL.acl.toCli()
                updatedCli = managedACL.acl.cli
                logging.debug("[aclm][updatePolicies] Updated CLI: {}".format(updatedCli))

                ## Update Policy
                policy['nvPairs']['CONF'] =  str(updatedCli)
                logging.debug("[aclm][updatePolicies] Updated Policy: {}".format(policy))
                output = self.putUpdatedPolicyById(policyId, policy)

                ## Mark Policy for Deployment
                logging.debug("[aclm][updatePolicies] Adding {} to toDeploy".format(policyId))
                managedACL.toDeploy.add(policyId)

            return
        else:
            logging.info("[aclm][updatePolicies] Policy content has not changed.  Policies will not be updated.")

    def deployPolicies(self, managedACL ):
        """
        Deploy managedACL.toDeploy list
        """
        logging.info("[aclm][deployPolicies] Deploying Pending Policies: {}".format(managedACL.toDeploy))

        ## Lookup Policy Cache for Serial Number
        outputCombined = {}
        for policyId in list(managedACL.toDeploy):
            serialNumber = self.POLICY_CACHE[policyId]['serialNumber']
            logging.debug("[aclm][deployPolicies] Deploying Pending Policies to Switch: {}".format(serialNumber))
            output = self.postDeployFabricSwitch(serialNumber)
            logging.debug("[aclm][deployPolicies] Output: {}".format(output))
            outputCombined[serialNumber]= output
        # output = self.postDeployPolicyList(list(managedACL.toDeploy))

        # Reset toDeploy List
        managedACL.toDeploy = set()

        return outputCombined

    # def updateAclm(self, jsonInput):
    #     """
    #     Update Existing Managed ACL
    #     """
    #     return

    def buildPending(self, pendingDict):
        """
        Create Pending (New) Managed ACL Objects from Session
        """
        logging.debug("[aclm][buildPending] Existing ACLs: {}".format(self.ACLS))
        for hash, aclmDict in pendingDict.items():
            if hash in list(self.ACLS.keys()):
                logging.debug("[aclm][buildPending] Pending ACL already in ACL dictonary - Skipping")
                continue
            else:
                # self.ACLS[hash] = aclmDict
                logging.debug("[aclm][buildPending] Building Pending ACL: {}".format(aclmDict))
                newACL = self.createAclm(aclmDict)
            #
            # ### Set Transient Details from Pending Dict
            # logging.debug("[aclm][buildPending] New ACL Hash: {}".format(newACL.hash))
            # if pendingDict.get('toAttach'):
            #     self.ACLS[newACL.hash].toAttach = set(pendingDict.get('toAttach'))
            # if pendingDict.get('toDetach'):
            #     self.ACLS[newACL.hash].toDetach = set(pendingDict.get('toDetach'))
            # if pendingDict.get('toDeploy'):
            #     self.ACLS[newACL.hash].toDeploy = set(pendingDict.get('toDeploy'))
                logging.debug("[aclm][buildPending] New ACL: {}".format(self.ACLS[newACL.hash]))

        return newACL.hash

    def createAclm(self, jsonInput):
        """
        Create New Managed ACL from JSON
        """

        # ## Reset ACL Dictionary
        # self.ACLS = {}

        newAclg = acl.acl_group()
        newAclg.fromJson(jsonInput['acl'])
        #newAclg.generateHash()

        outputObj = json.loads(newAclg.json())
        logging.debug("[aclm][createAclm] JSON: {}".format(outputObj))
        hash = outputObj['hash']
        keylist = list(self.ACLS.keys())
        logging.debug("[aclm][createAclm] Existing Managed Key List: {}".format(keylist))
        logging.debug("[aclm][createAclm] New ACL Hash: {}".format(hash))

        if hash in list(self.ACLS.keys()):
            ## Entry already exists
            raise Exception("Cannot create new Managed ACL - ACL already exists")
            # logging.error("[aclm][createAclm] Cannot create new Managed ACL - ACL already exists. Returning existing ACL")
            # return self.ACLS[hash]

        else:
            self.ACLS[hash] = managedACL(outputObj['name'], hash, None, None, newAclg)

            ### toAttach
            if jsonInput.get('toAttach') and len(jsonInput['toAttach']) > 0:
                self.ACLS[hash].toAttach = set(jsonInput['toAttach'])
                logging.debug("[aclm][createAclm] Updating toAttach {}".format(self.ACLS[hash].toAttach))

            ### toDetach
            if jsonInput.get('toDetach') and len(jsonInput['toDetach']) > 0:
                self.ACLS[hash].toDetach = set(jsonInput['toDetach'])
                logging.debug("[aclm][createAclm] Updating toDetach {}".format(self.ACLS[hash].toDetach))

            ### toDeploy
            if jsonInput.get('toDeploy') and len(jsonInput['toDeploy']) > 0:
                self.ACLS[hash].toDeploy = set(jsonInput['toDeploy'])
                logging.debug("[aclm][createAclm] Updating toDeploy {}".format(self.ACLS[hash].toDeploy))

            logging.info("[aclm][createAclm] Created new Managed ACL Object from JSON: {}".format(self.ACLS[hash]))
            return self.ACLS[hash]

    def deleteAclm(self, hash):
        """
        Delete Managed ACL by Hash ID
        """

        keylist = list(self.ACLS.keys())
        logging.debug("[aclm][deleteAclm] Hash to Delete: {}".format(hash))
        logging.debug("[aclm][deleteAclm] Existing Managed Key List: {}".format(keylist))

        managedACL = self.ACLS[hash]

        deletedPolicies = []
        output = None
        if managedACL.status == "Applied":
            # Delete Policies from DCNM
            for serialNumber, policyId in managedACL.policies.items():

                ## Delete Policy
                output = self.deletePolicyById(policyId)
                logging.info("[aclm][deleteAclm] Policy - {} - Deleted from Serial Number: {}".format(policyId, serialNumber))
                # self.putMarkPolicyDeleteById(policyId)
                deletedPolicies.append(policyId)

            # # (Un)deploy Policies
            # self.deployPolicies(deletedPolicies)
            # output = self.postDeployPolicyList(deletedPolicies)
            # output = self.deployPolicies(managedACL)

        ## Lookup Policy Cache for Serial Number
        outputCombined = {}
        for policyId in deletedPolicies:
            serialNumber = self.POLICY_CACHE[policyId]['serialNumber']
            logging.debug("[aclm][deleteAclm] Deploying Pending Policies to Switch: {}".format(serialNumber))
            output = self.postDeployFabricSwitch(serialNumber)
            logging.debug("[aclm][deleteAclm] Output: {}".format(output))
            outputCombined[serialNumber]= output

        # Remove from ACLS
        self.ACLS.pop(hash)

        return {"deletedOk": hash, "deletedPolicies": deletedPolicies, "deployOutput": outputCombined}
