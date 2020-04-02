import logging
import requests
import json
from requests.auth import HTTPBasicAuth
from requests import HTTPError

from acl import acl


class managedACL():
    """
    Managed ACL Object
    - Hash
    - Name
    - Serial Number:Policy-ID Dictionary
    - ACL Object

    """
    name = None
    hash = None
    policies = {}
    acl = None
    toAttach = set()
    toDetach = set()
    toDeploy = [] #list of Policy-IDs to deploy

    def __init__(self, name, hash, serialNumber, policyId, aclObject):
        self.name = name
        self.hash = hash
        self.policies[serialNumber] = policyId
        self.acl = aclObject
        return

    def appendSwitch(self, serialNumber, policyId):
        """
        Add switches with same Managed ACL policy content to object
        - Does NOT create or update policies
        """
        self.policies[serialNumber] = policyId
        return

    def __str__(self):
        return str({
        'name': self.name,
        'hash': self.hash,
        'policies': self.policies,
        'acl': str(self.acl),
        'toAttach': str(self.toAttach),
        'toDetach': str(self.toDetach)
        })

    def markAttachACLtoSwitch(self, serialNumber):
        if serialNumber not in list(self.policies.keys()):
            self.toAttach.add(serialNumber)
            self.toDetach.discard(serialNumber)
            logging.info("Attached ACL to Serial Number: {}".format(serialNumber))
            return
        else:
            raise Exception("ACL already attached to serial number: {}".format(serialNumber))

    def markDetachACLfromSwitch(self, serialNumber):
        if serialNumber in list(self.policies.keys()):
            self.toDetach.add(serialNumber)
            self.toAttach.discard(serialNumber)
            logging.info("Detached ACL from Serial Number: {}".format(serialNumber))
            return
        else:
            raise Exception("ACL already detached from serial number: {}".format(serialNumber))
    # def removeSwitch(self, serialNumber):
    #     self.POLICIES.pop(serialNumber, None)
    #     return


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
    DCNM_FQDN = None
    DCNM_TOKEN = None
    DCNM_USERNAME = None
    DCNM_PASSWORD = None
    DCNM_SESSION = None

    DCNM_SOURCE = "ACLM"

    ACLS = {}

    def __init__(self, DCNM_FQDN = "10.67.29.26", DCNM_USERNAME = "apiuser", DCNM_PASSWORD = "C!sco123"):
        self.DCNM_FQDN = DCNM_FQDN
        self.DCNM_USERNAME = DCNM_USERNAME
        self.DCNM_PASSWORD = DCNM_PASSWORD
        return

    def userLogon(self, expiry = 18000):
        url = "https://{}/rest{}".format(self.DCNM_FQDN, "/logon")
        payload = {"expirationTime": expiry}
        self.DCNM_SESSION = requests.Session()
        r = self.DCNM_SESSION.post(url, json=payload, verify=False, auth=HTTPBasicAuth(self.DCNM_USERNAME, self.DCNM_PASSWORD))
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
            self.DCNM_TOKEN = r.json()['Dcnm-Token']
            if self.DCNM_TOKEN == None:
                raise Exception("DCNM Token not found - Exiting")
            else:
                return

    def dcnmApiWrapper(self, method, path, payload = None):
        if self.DCNM_SESSION == None:
            logging.debug("No Current DCNM_SESSION Found - Logging In")
            self.userLogon()
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

    def getFabrics(self):
        path = "/control/fabrics"
        output = self.dcnmApiWrapper("get", path)
        return output

    def getFabricInventory(self, fabricName):
        path = "/control/fabrics/{}/inventory".format(str(fabricName))
        output = self.dcnmApiWrapper("get", path)
        return output

    def getPolicyById(self, policyId):
        path = "/control/policies/{}".format(policyId)
        output = self.dcnmApiWrapper("get", path)
        return output

    def getPolicyListBySwitch(self, serialNumber, sourceName = None):
        path = "/control/policies/switches/{}?source={}".format(serialNumber, sourceName)
        output = self.dcnmApiWrapper("get", path)
        logging.debug(type(output))
        if type(output) != type(list()):
            logging.debug("Converting to List")
            output = [output]
        return output

    def getPolicyListBySwitches(self, serialNumberList, sourceName = DCNM_SOURCE):
        serialNumbers = ",".join(serialNumberList)
        path = "/control/policies/switches?serialNumber={}&source={}".format(serialNumbers, sourceName)
        output = self.dcnmApiWrapper("get", path)
        logging.debug(type(output))
        if type(output) != type(list()):
            logging.debug("Converting to List")
            output = [output]
        return output

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
        payload = {}
        payload['description'] = "REST API TEST POLICY"
        payload['serialNumber'] = serialNumber
        payload['entityType'] = "SWITCH"
        payload['entityName'] = "SWITCH"
        payload['templateName'] = "switch_freeform"
        payload['templateContentType'] = "PYTHON"
        payload['nvPairs'] = {}
        payload['nvPairs']['CONF'] = content
        payload['source'] = DCNM_SOURCE
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

    def deletePolicyById(self, policyId):
        path = "/control/policies/{}".format(policyId)
        output = self.dcnmApiWrapper("delete", path)
        return output

    def processPolicies(self, jsonList):
        """
        Iterate list of ACLM source polcies and convert to list of ACL python objects
        """

        ## Reset ACL Dictionary
        self.ACLS = {}

        for output in jsonList:
            logging.debug("Process Policy: {}".format(output))
            aclContent = output['nvPairs']['CONF']
            logging.debug("Policy Content: {}".format(aclContent))

            newAcl = acl.acl_group()
            newAcl.fromCli(aclContent)
            outputObj = json.loads(newAcl.json())

            logging.debug("JSON: {}".format(outputObj))
            #logging.debug("ACL Dict: {}".format(self.ACLS))

            hash = outputObj['hash']
            keylist = list(self.ACLS.keys())
            logging.debug("Key List: {}".format(keylist))
            logging.debug("Hash: {}".format(hash))

            try:
                self.ACLS[hash].appendSwitch(output['serialNumber'], output['policyId'])
                logging.info("Added {} to Managed ACL Object: {}".format(output['serialNumber'],self.ACLS))
            except KeyError:
                self.ACLS[hash] = managedACL(outputObj['name'], hash, output['serialNumber'], output['policyId'], newAcl)
                logging.info("Created new Managed ACL Object: {}".format(self.ACLS))

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
            logging.debug("Attaching ACL to new switch(es)")
            deltaToAttach = set()
            for serialNumber in managedACL.toAttach:
                ## Add New Policy
                payload = self.buildPolicyPayload(serialNumber, managedACL.acl.toCli())
                output = self.postNewPolicy(payload)
                logging.debug("New Policy Response: {}".format(output))
                policyId = output['policyId']
                logging.info("Policy - {} - Added to Serial Number: {}".format(policyId, serialNumber))

                ## Add to managedACL policy dict.
                managedACL.policies[serialNumber] = policyId

                ## Mark Policy for Deployment
                managedACL.toDeploy.append(policyId)

                ## Remove for toAttach set
                deltaToAttach.add(serialNumber)

            ## Update toAttach
            managedACL.toAttach.difference_update(deltaToAttach)

        else:
            logging.info("No new switches attached to ACL")

        ## Check toDetach
        if len(managedACL.toDetach) > 0:
            logging.debug("Detaching ACL from switch(es)")
            deltaToDetach = set()
            for serialNumber in managedACL.toDetach:
                ## Get Policy
                logging.debug("Serial Number: {}".format(serialNumber))
                policyId = managedACL.policies[serialNumber]

                ## Delete Policy
                output = self.deletePolicyById(policyId)
                logging.info("Policy - {} - Deleted from Serial Number: {}".format(policyId, serialNumber))

                ## Remove from managedACL policy dict.
                managedACL.policies.pop(serialNumber)

                ## Remove for toDetach set
                deltaToDetach.add(serialNumber)

            ## Update toAttach
            managedACL.toDetach.difference_update(deltaToDetach)

        else:
            logging.info("No switches dettached from ACL")

        ## Check if empty!
        if len(managedACL.policies) == 0:
            logging.warning("No switches attached to ACL.  This ACL will be totally removed")
            logging.debug(managedACL.acl.toCli())

        ## Check Content Hash
        if managedACL.acl.hash != managedACL.hash:
            ## Content has changed - Push update

            ## Iterate Existing Switch Policies
            for serialNumber, policyId in managedACL.policies.items():
                ## Get Policy
                logging.debug("Serial Number: {}".format(serialNumber))
                policy = self.getPolicyById(policyId)
                logging.debug("Existing Policy: {}".format(policy))
                updatedCli = managedACL.acl.toCli()
                logging.debug("Updated CLI: {}".format(updatedCli))

                ## Update Policy
                policy['nvPairs']['CONF'] =  str(updatedCli)
                logging.debug("Updated Policy: {}".format(policy))
                output = self.putUpdatedPolicyById(policyId, policy)

                ## Mark Policy for Deployment
                managedACL.toDeploy.append(policyId)

            return
        else:
            logging.info("Policy content has not changed.  Policies will not be updated.")

    def deployPolicies(self, managedACL ):
        """
        Deploy managedACL.toDeploy list
        """
        logging.info("Deploying Pending Policies: {}".format(managedACL.toDeploy))
        output = self.postDeployPolicyList(managedACL.toDeploy)
        return
