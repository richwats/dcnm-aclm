import logging
logging.basicConfig(level=logging.DEBUG)
# from aclm import aclm

#from datetime import datetime
from flask import Flask, session
from flask_restx import Resource, Api, reqparse, inputs, fields, marshal

from aclm import aclm
from myWildcard import MyWildcard

#testing
import json

# FDO22192XCF,FDO21521S70
# "FDO22192XCF","FDO21521S70"

###  Authorizations

authorizations = {
    'cookieAuth': {
        'type': 'apiKey',
        'in': 'cookie',
        'name': 'session'
    }
}

app = Flask(__name__)
api = Api(app, version='1.0', title='ACL Manager REST API',
    description='REST API for DCNM ACL Manager',
    authorizations=authorizations)

# cookieDomain = app.session_interface.get_cookie_domain(app)
# logging.debug("Cookie Domain: {}".format(cookieDomain))

### Setup Session ###
app.secret_key = b'??%_a?d??vX?,'

### Build/Load ACLM Object from Session ###



# ## Doesn't work can't access session out of context...
# if 'token' not in list(session.keys()):
#     ## Not Logged On
#     pass
# else:
#     ## Logging On - Restore ACLM object state
#     flask_aclm = aclm()
#     pass

# def sessionCheck():
#     if 'dcnm-token' not in list(session.keys()):
#         api.abort(401, e.__doc__, status = "Not Logged In", statusCode = "401")
#     else:
#         return True


def buildAclmFromSession(updateCache = False, clearPending = False):

    ## Build from Session
    logging.debug("[restServer][buildAclmFromSession] Building ACLM from Session: updateCache:{}".format(updateCache))
    logging.debug("[restServer][buildAclmFromSession] Session State: {}".format(session))
    session['UPDATE_CACHE'] = updateCache
    flask_aclm = aclm(**session)

    ## Reset False
    session['UPDATE_CACHE'] = False

    ## Update JSON Cache
    session['POLICY_CACHE'] = flask_aclm.POLICY_CACHE  # change name to POLICY_CACHE

    ## Update Expiry Timer
    session['DCNM_EXPIRY'] = flask_aclm.DCNM_EXPIRY

    ## Update Fabric Inventory
    session['FABRIC_INVENTORY'] = flask_aclm.FABRIC_INVENTORY

    if clearPending:
        session['PENDING'] = {}

    else:
        pendingDict = session.get('PENDING')
        if len(pendingDict) > 0:
            logging.debug("[restServer][buildAclmFromSession] Pending New ACLs: {}".format(pendingDict))

            # if type(pendingList) != type(list()):
            #     session['PENDING'] = list()
            #     return flask_aclm

            # outputList = []
            # for pending in pendingList:
            #     outputList.append(pending)
            #
            # logging.debug("[restServer][buildAclmFromSession] Modified List: {}".format(outputList))
            flask_aclm.buildPending(pendingDict)

    return flask_aclm


## Models

aclModel = api.model('aclModel', {
    'aclType': fields.String,
    'aclProtocol': fields.String,
    'remarks': fields.String,
    'sourceIpMask': fields.String,
    'sourceOperator': fields.String,
    'sourcePortStart': fields.String,
    'sourcePortStop': fields.String,
    'destIpMask': fields.String,
    'destOperator': fields.String,
    'destPortStart': fields.String,
    'destPortStop': fields.String,
    'extra': fields.String,

})

wild_str = fields.Wildcard(fields.String)
wild_acl = MyWildcard(fields.Nested(aclModel, skip_none=True))

entryModel = api.model('entryModel', {
    '*': wild_acl
})

policyModel = api.model('policyModel', {
    '*': wild_str
})

aclgModel = api.model('aclgModel', {
    'name': fields.String,
    'hash': fields.String,
    ### Wildcard can't cope with integer keys!!!
    'entries': fields.Nested(entryModel, skip_none=True)
    # 'entries': fields.String
})

deployOuputModel = api.model('deployOuputModel', {
    'switchSN': fields.String,
    'successPTIList': fields.String
})


managedAclModel = api.model('aclmModel', {
    'name': fields.String,
    'hash': fields.String,
    'status': fields.String,
    'policies': fields.Nested(policyModel, required=False, skip_none=True),
    'acl': fields.Nested(aclgModel, skip_none=True),
    'toAttach': fields.List(fields.String, skip_none=True),
    'toDetach': fields.List(fields.String, skip_none=True),
    'toDeploy': fields.List(fields.String, skip_none=True),
    'deployOutput': fields.List(fields.Nested(deployOuputModel, skip_none=True), required=False, skip_none=True)
})

newAclModel = api.model('newAclModel', {
    'name': fields.String,
    'hash': fields.String,
    'status': fields.String,
    'acl': fields.Nested(aclgModel, required=False, skip_none=True),
    'toAttach': fields.List(fields.String, required=True),
    'toDetach': fields.List(fields.String, required=False, skip_none=True)
})

"""
dcnmLogon
dcnmLogout
selectSwitches
aclmByHash

createNewAclm

"""

### HORRIBLY INSECURE!!!
@api.route('/logon')
@api.param('username','DCNM Username', type=str, default="apiuser")
@api.param('password','DCNM Password', type=str, default="C!sco123")
@api.param('server','DCNM Server', type=str, default="10.67.29.26")
class dcnmLogon(Resource, ):
    def get(self):
        """
        Sets up Flask session with DCNM session token
        """
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, location='args')
        parser.add_argument('password', type=str, required=True, location='args')
        parser.add_argument('server', type=str, required=True, location='args')
        args = parser.parse_args()
        logging.debug("[dcnmLogon][get] Parsed Arguments: {}".format(args))
        username = args['username']
        password = args['password']
        server = args['server']

        session['DCNM_USERNAME'] = username
        session['DCNM_PASSWORD'] = password
        session['DCNM_FQDN'] = server

        flask_aclm =  aclm(**{'DCNM_FQDN':server, 'DCNM_USERNAME':username, 'DCNM_PASSWORD':password})
        flask_aclm.userLogon() # Required to set token?

        ## Set Expiry Timer & Token in Session
        session['DCNM_EXPIRY'] = flask_aclm.DCNM_EXPIRY
        session['DCNM_TOKEN'] = flask_aclm.DCNM_TOKEN


        ## Current Managed ACLM Hash IDs for Fabric
        session['ACLM_OBJECTS'] = {}

        ## Set Pending ACL Dictionary
        session['PENDING'] = {}

        # ## Set Selected Serial Numbers
        # session['SELECTED_SERIAL_NUMBERS'] = []

        ## Set Selected Serial Numbers
        session['SELECTED_FABRIC'] = None
        session["FABRIC_INVENTORY"] = None
        session['POLICY_CACHE'] = None

        logging.debug("[dcnmLogon][get] Session: {}".format(session))

        return {'logonStatus':'OK'}


@api.route('/logout')
class dcnmLogout(Resource):
    @api.doc(security='session')
    def get(self):
        """
        Logout of DCNM
        Clear Flask Session
        Clear Cookie?
        """
        try:
            flask_aclm = buildAclmFromSession(False, True)
            output = flask_aclm.userLogout()
            logging.debug("[dcnmLogout][get] Output: {}".format(output))

            ## Clear Session
            session.clear()
            logging.debug("[dcnmLogout][get] Session: {}".format(session))

            return {'logoutStatus':'OK'}

        ### Catch All Exception
        except Exception as e:
            logging.error(e)
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")



@api.route('/policy/selectFabric')
@api.param('fabricName','Fabric scope for ACLs', type=str, default="DC3")
@api.param('updateCache','Force update of JSON policies cache', type=bool, default=False)
class selectFabric(Resource):
    @api.doc(security='session')
    def get(self):
        """
        Builds Managed ACL Objects for switches in selected fabric and returns dictonary of hash IDs
        """
        parser = reqparse.RequestParser()
        parser.add_argument('fabricName', required=True, type=str, location='args')
        parser.add_argument('updateCache', type=inputs.boolean, location='args')
        args = parser.parse_args()
        logging.debug("[selectFabric][get] Parsed Arguments: {}".format(args))
        fabricName = args['fabricName']
        updateCache = args['updateCache']

        # ## Get Currently Selected Switches
        # sessionSerialNumbers = session.get('SELECTED_SERIAL_NUMBERS')
        # logging.debug("[selectFabric][get] Currently Selected Switches: {}".format(sessionSerialNumbers))

        ## Build ACLM
        if fabricName != session['SELECTED_FABRIC'] and len(session['PENDING']) > 0:
            clearPending = True
            logging.warning("[selectFabric][get] New fabric selected clearing pending changes.")
        else:
            clearPending = False

        ## Set Selected Fabric Name
        session['SELECTED_FABRIC'] = fabricName
        flask_aclm = buildAclmFromSession(updateCache, clearPending)

        # ## Get Inventory of selcted Fabric
        # inventoryList = flask_aclm.getFabricInventory(fabricName)
        # output = flask_aclm.processInventory(inventoryList)

        # ## Set Fabric Inventory in Session
        # session["FABRIC_INVENTORY"] = output

        ## Return Default view of ACLM Objects
        keylist = list(flask_aclm.ACLS.keys())
        for key in keylist:
            logging.debug("[selectFabric][get] Processing Key: {}".format(key))
            managedACL = flask_aclm.ACLS[key]
            session['ACLM_OBJECTS'][key] = {
                'name': managedACL.name,
                'hash': key,
                'status': managedACL.status,
                # 'toAttach': list(postUpdateAcl.toAttach),
                # 'toDetach': list(postUpdateAcl.toDetach),
                'toDeploy': list(managedACL.toDeploy),
                }

        return session['ACLM_OBJECTS']


        ## Warn if pending ACLs and changing scope?


        # serialNumberList = args['serialNumbers']
        # logging.debug("[selectFabric][get] Parsed Selected Switches: {}".format(serialNumberList))
        #
        # try:
        #     ## Add Selected Switches to Session Cache
        #     updateCache = args['updateCache']
        #     if session.get('SELECTED_SERIAL_NUMBERS') == None:
        #         ## No Previously Selected Switches
        #         updateCache = True
        #
        #         ## Combines Selected & Pending ACLs
        #         updatedSerialNumbers = set(serialNumberList).union(set(session['SELECTED_SERIAL_NUMBERS']))
        #         session['SELECTED_SERIAL_NUMBERS'] = list(updatedSerialNumbers)
        #         logging.debug("[selectSwitches][get] No Previously Selected Switches - Updating Policies")
        #
        #     elif len(set(sessionSerialNumbers).symmetric_difference(set(serialNumberList))) != 0:
        #         ## Selected Switches Changed
        #         updateCache = True
        #
        #         ## Combines Selected & Pending ACLs
        #         updatedSerialNumbers = set(serialNumberList).union(set(session['SELECTED_SERIAL_NUMBERS']))
        #         session['SELECTED_SERIAL_NUMBERS'] = list(updatedSerialNumbers)
        #         logging.debug("[selectSwitches][get] Selected Switches Changed - Updating Policies")
        #
        #     else:
        #         logging.debug("[selectSwitches][get] No change in selected switches.  Using session cache")
        #
        #     ## Add to Session
        #     flask_aclm = buildAclmFromSession(updateCache)
        #
        #     ## Return Default view of ACLM Objects
        #     jsonOutput = {}
        #     keylist = list(flask_aclm.ACLS.keys())
        #     for key in keylist:
        #         logging.debug("[selectSwitches][get] Processing Key: {}".format(key))
        #         managedACL = flask_aclm.ACLS[key]
        #         jsonOutput[key] = {'name': managedACL.name, 'hash': key}
        #
        #     return jsonOutput
        #
        # ### Catch All Exception
        # except Exception as e:
        #     logging.error("[selectSwitches][get] Error: {}".format(e))
        #     api.abort(500, e.__doc__, status = str(e), statusCode = "500")
        #
        # return jsonList



# @api.route('/policy/selectSwitches')
# @api.param('serialNumbers','Comma separated list of serial numbers', type=str, default="FDO22192XCF,FDO21521S70")
# @api.param('updateCache','Force update of JSON policies cache', type=bool, default=False)
# class selectSwitches(Resource):
#     #@api.marshal_with(serialNumbers, as_list=True)
#     @api.doc(security='session')
#     def get(self):
#         """
#         Builds Managed ACL Objects for selected switches and returns dictonary of hash IDs
#         """
#         ## DONT Build ACLM
#         # flask_aclm = aclm(**session)
#
#         # FDO22192XCF,FDO21521S70
#         # "FDO22192XCF","FDO21521S70"
#         parser = reqparse.RequestParser()
#         # Look only in the querystring
#         parser.add_argument('serialNumbers', required=True, type=str, location='args', action='split')
#         parser.add_argument('updateCache', type=inputs.boolean, location='args')
#         args = parser.parse_args()
#         logging.debug("[selectSwitches][get] Parsed Arguments: {}".format(args))
#
#         sessionSerialNumbers = session.get('SELECTED_SERIAL_NUMBERS')
#         logging.debug("[selectSwitches][get] Currently Selected Switches: {}".format(sessionSerialNumbers))
#         serialNumberList = args['serialNumbers']
#         logging.debug("[selectSwitches][get] Parsed Selected Switches: {}".format(serialNumberList))
#         # test = set(sessionSerialNumbers).symmetric_difference(set(serialNumberList))
#         # logging.debug(test)
#
#         try:
#             ## Add Selected Switches to Session Cache
#             updateCache = args['updateCache']
#             if session.get('SELECTED_SERIAL_NUMBERS') == None:
#                 ## No Previously Selected Switches
#                 updateCache = True
#
#                 ## Combines Selected & Pending ACLs
#                 updatedSerialNumbers = set(serialNumberList).union(set(session['SELECTED_SERIAL_NUMBERS']))
#                 session['SELECTED_SERIAL_NUMBERS'] = list(updatedSerialNumbers)
#                 logging.debug("[selectSwitches][get] No Previously Selected Switches - Updating Policies")
#
#             elif len(set(sessionSerialNumbers).symmetric_difference(set(serialNumberList))) != 0:
#                 ## Selected Switches Changed
#                 updateCache = True
#
#                 ## Combines Selected & Pending ACLs
#                 updatedSerialNumbers = set(serialNumberList).union(set(session['SELECTED_SERIAL_NUMBERS']))
#                 session['SELECTED_SERIAL_NUMBERS'] = list(updatedSerialNumbers)
#                 logging.debug("[selectSwitches][get] Selected Switches Changed - Updating Policies")
#
#             else:
#                 logging.debug("[selectSwitches][get] No change in selected switches.  Using session cache")
#
#             ## Add to Session
#             #logging.debug('Update Cache: {}'.format(updateCache))
#             flask_aclm = buildAclmFromSession(updateCache)
#
#             ## Return Default view of ACLM Objects
#             jsonOutput = {}
#             keylist = list(flask_aclm.ACLS.keys())
#             for key in keylist:
#                 logging.debug("[selectSwitches][get] Processing Key: {}".format(key))
#                 managedACL = flask_aclm.ACLS[key]
#                 jsonOutput[key] = {'name': managedACL.name, 'hash': key}
#
#             return jsonOutput
#
#         ### Catch All Exception
#         except Exception as e:
#             logging.error("[selectSwitches][get] Error: {}".format(e))
#             api.abort(500, e.__doc__, status = str(e), statusCode = "500")
#
#         return jsonList

@api.route('/aclm/')
@api.param('autoDeploy','Automatically deploy new policies', type=bool, default=False)
class newAclm(Resource):
    @api.doc(security='session')
    @api.marshal_with(newAclModel)
    @api.expect(newAclModel)
    def post(self):
        """
        Create New Managed ACL
        """
        try:
            ## Build ACLM
            flask_aclm = buildAclmFromSession()
            logging.info("[newAclm][post] Create New Managed ACL")
            logging.debug("[newAclm][post] Payload: {}".format(api.payload))
            managedACL = flask_aclm.createAclm(api.payload)

            ### Add to Session?
            # if session.get('PENDING') == None:
            #     session['PENDING'] = []
            # elif type(session['PENDING']) != type(list()):
            #     session['PENDING'] = []

            session['PENDING'][managedACL.hash] = managedACL.toDict()
            logging.debug("[newAclm][post] Current Session Pending: {}".format(session['PENDING']))

            # ## Update Session ACLM Dict
            # session['ACLM_OBJECTS'][newHash] = {
            #     'name': postUpdateAcl.name,
            #     'hash': newHash,
            #     'status': postUpdateAcl.status,
            #     # 'toAttach': list(postUpdateAcl.toAttach),
            #     # 'toDetach': list(postUpdateAcl.toDetach),
            #     'toDeploy': list(postUpdateAcl.toDeploy),
            #     }

            return managedACL.toDict()

        except Exception as e:
            logging.error("[newAclm][post] Error: {}".format(e))
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")

@api.route('/aclm/<string:hash>')
@api.param('hash','Managed ACL Object Hash')
class aclmByHash(Resource):
    #@api.marshal_with(serialNumbers, as_list=True)
    @api.doc(security='session')
    def get(self, hash):
        """
        Returns Managed ACL Objects for selected hash ID. Requires built ACLM object(s).
        """
        ## Build ACLM
        flask_aclm = buildAclmFromSession()

        logging.debug("[aclmByHash][get] Selected Hash: {}".format(hash))
        logging.debug("[aclmByHash][get] ACLS: {}".format(flask_aclm.ACLS))
        try:
            managedACL = flask_aclm.ACLS[hash]
            return managedACL.toDict()
        except KeyError as e:
            logging.error("[aclmByHash][post] KeyError: {}".format(e))
            api.abort(404, e.__doc__, status = str(e), statusCode = "404")
        except Exception as e:
            logging.error("[aclmByHash][post] Error: {}".format(e))
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")

    @api.doc(security='session')
    @api.marshal_with(managedAclModel)
    @api.expect(managedAclModel)
    @api.param('autoDeploy','Automatically deploy updated policies', type=bool, default=False)
    def put(self, hash):
        """
        Update Managed ACL for selected hash ID
        """
        try:
            ## Get Args
            parser = reqparse.RequestParser()
            parser.add_argument('autoDeploy', type=inputs.boolean, location='args')
            args = parser.parse_args()
            autoDeploy = args['autoDeploy']


            ## Build ACLM
            flask_aclm = buildAclmFromSession()

            logging.info("[aclmByHash][put] Update Managed ACL. Hash:{}".format(hash))
            logging.debug("[aclmByHash][put] Payload: {}".format(api.payload))

            ## Get Existing Managed ACL Object
            managedACL = flask_aclm.ACLS[hash]
            logging.debug("[aclmByHash][put] Initial ACL Object: {}".format(managedACL))
            updatedACL = managedACL.updateFromJson(api.payload)

            ## Update Policies in DCNM
            flask_aclm.updatePolicies(managedACL)

            ## AutoDeploy
            deployOutput = None
            if autoDeploy and len(managedACL.toDeploy) > 0:
                deployOutput = flask_aclm.deployPolicies(managedACL)

            ## Remove Pending ACL
            if managedACL.hash in list(session['PENDING'].keys()):
                session['PENDING'].pop(managedACL.hash)

            ## Rebuild Session ACLM Objects
            keylist = list(flask_aclm.ACLS.keys())
            for key in keylist:
                logging.debug("[aclmByHash][put] Rebuilding Session ACLM Objects: {}".format(key))
                managedACL = flask_aclm.ACLS[key]
                session['ACLM_OBJECTS'][key] = {
                 'name': managedACL.name,
                 'hash': key,
                 'status': managedACL.status,
                 # 'toAttach': list(postUpdateAcl.toAttach),
                 # 'toDetach': list(postUpdateAcl.toDetach),
                 'toDeploy': list(managedACL.toDeploy),
                 }

            ## Clear Cache
            flask_aclm = buildAclmFromSession(True)

            ## Get Updated Hash
            newHash = updatedACL['acl']['hash']
            postUpdateAcl = flask_aclm.ACLS[newHash]
            #logging.debug("[aclmByHash][put] Post Update ACL Object: {}".format(postUpdateAcl))

            # #return updatedACL.toDict()
            # try:
            #     marshal(updatedACL,managedAclModel)
            # except Exception as e:
            #     logging.error(e)

            # test = marshal(postUpdateAcl,managedAclModel)
            # logging.debug("[aclmByHash][put] Marshal Test: {}".format(test))

            # ## Update Session ACLM Dict
            # session['ACLM_OBJECTS'][newHash] = {
            #     'name': postUpdateAcl.name,
            #     'hash': newHash,
            #     'status': postUpdateAcl.status,
            #     # 'toAttach': list(postUpdateAcl.toAttach),
            #     # 'toDetach': list(postUpdateAcl.toDetach),
            #     'toDeploy': list(postUpdateAcl.toDeploy),
            #     }


            output = postUpdateAcl.toDict()
            output['deployOutput'] = deployOutput
            logging.debug("[aclmByHash][put] Post Update ACL Object: {}".format(output))
            return output

        except Exception as e:
            logging.error("[aclmByHash][put] Error: {}".format(e))
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")

    @api.doc(security='session')
    #@api.marshal_with(managedAclModel)
    #@api.expect(managedAclModel)
    def delete(self, hash):
        """
        Delete Managed ACL for selected hash ID
        """
        try:
            ## Build ACLM
            flask_aclm = buildAclmFromSession()

            logging.info("[aclmByHash][delete] Delete Managed ACL. Hash:{}".format(hash))

            ## Get Existing Managed ACL Object
            #managedACL = flask_aclm.ACLS[hash]
            #logging.debug("[aclmByHash][delete] Initial ACL Object: {}".format(managedACL))
            resp = flask_aclm.deleteAclm(hash)

            # ## Update Policies in DCNM
            # flask_aclm.updatePolicies(managedACL)

            ## Clear Cache & Pending
            flask_aclm = buildAclmFromSession(True, True)

            return resp

        except KeyError as e:
            logging.error("[aclmByHash][delete] KeyError: {}".format(e))
            api.abort(404, e.__doc__, status = str(e), statusCode = "404")
        except Exception as e:
            logging.error("[aclmByHash][delete] Error: {}".format(e))
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")


@api.route('/test/session')
class dumpSession(Resource):
    @api.doc(security='session')
    def get(self):
        """
        Returns Current Session Details
        """
        output = {}
        for key,value in session.items():
            output[key] = value

        return output

if __name__ == '__main__':
    app.run(debug=True)

"""
#export FLASK_APP=flask.py; export FLASK_DEBUG=1
#flask run -h 0.0.0.0

jsonList = testACLM.getPolicyListBySwitches(["FDO22192XCF","FDO21521S70"])
#@api.doc(responses={ 200: 'OK', 400: 'Invalid Argument' }, params={ 'serialNumberList': 'List of device serial numbers' })

@api.route('/policy/policyListBySwitches')
class getPolicyListBySwitches(Resource):
	def get(self, serialNumberList):
        return {'hello: 'world'}
        # logging.info("getPolicyListBySwitches: {}".format(serialNumberList))
        # try:
        #     jsonList = flask_aclm.getPolicyListBySwitches(serialNumberList)
        # except Exception as e:
        #     api.abort(400, e.__doc__, status = "Invalid Argument", statusCode = "400")
        #
        # # return {
        # # 	"status": "Got new data"
        # # }
        # return jsonList

"""

# app2 = Api(app = flask_app,
#             version = "0.1",
#             title = "DCNM ACL Manager REST API",
#             description = "Manage ACLs across DCNM managed fabrics"
#           )
#
# aclm_namespace = app2.namespace('aclm', description='ACL Manager APIs')
#
# ### Setup Session ###
#
# ### Build/Load ACLM Object ###
# flask_aclm =  aclm()
#
# @aclm_namespace.route("/policy/policyListBySwitches")
# class getPolicyListBySwitches(Resource):
#     """
#     jsonList = testACLM.getPolicyListBySwitches(["FDO22192XCF","FDO21521S70"])
#     """
#     @app2.doc(responses={ 200: 'OK',
#                          400: 'Invalid Argument' },
# 			 params={ 'serialNumberList': 'List of device serial numbers' })
# 	def get(self, serialNumberList):
#         logging.info("getPolicyListBySwitches: {}".format(serialNumberList))
#         try:
#             jsonList = flask_aclm.getPolicyListBySwitches(serialNumberList)
#         except Exception as e:
#             aclm_namespace.abort(400, e.__doc__, status = "Invalid Argument", statusCode = "400")
#
#         # return {
# 		# 	"status": "Got new data"
# 		# }
#         return jsonList
