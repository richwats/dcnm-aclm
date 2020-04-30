import logging
logging.basicConfig(level=logging.DEBUG)
# from aclm import aclm

#from datetime import datetime
from flask import Flask, session, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_restx import Resource, Api, reqparse, inputs, fields, marshal, apidoc
from flask_cors import CORS
## Flask-Session
from flask_session import Session

from aclm import aclm
from myWildcard import MyWildcard

#testing
import json

## Environment
import os

from werkzeug.exceptions import HTTPException

DCNM_MGMT_VIP = os.environ.get("DCNM_MGMT_VIP", default="false")
logging.info("[restServer] Environment DCNM_MGMT_VIP: {}".format(DCNM_MGMT_VIP))

BASE_PATH = os.environ.get("BASE_PATH", default="/")
logging.info("[restServer] Environment BASE_PATH: {}".format(BASE_PATH))

# FDO22192XCF,FDO21521S70
# "FDO22192XCF","FDO21521S70"

###  Authorizations

authorizations = {
    'directAuth': {
        'type': 'apiKey',
        'in': 'cookie',
        'name': 'session'
    },
    'username': {
        'type': 'apiKey',
        'in': 'cookie',
        'name': 'username'
    },
    'resttoken': {
        'type': 'apiKey',
        'in': 'cookie',
        'name': 'resttoken'
    }
}

app = Flask(__name__)

## Fix for Swagger Absolute URLs
@apidoc.apidoc.add_app_template_global
def swagger_static(filename):
    return "./swaggerui/{0}".format(filename)


# app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_port=1, x_for=1, x_host=1, x_prefix=1)

# # Fix of returning swagger.json on HTTP
# @property
# def specs_url(self):
#     """
#     The Swagger specifications absolute url (ie. `swagger.json`)
#
#     :rtype: str
#     """
#     return url_for(self.endpoint('specs'), _external=False)
#

## Fix for Swagger
if BASE_PATH != "/":
    Api.base_path=BASE_PATH

## Restx API
api = Api(app, version='1.0', title='ACL Manager REST API',
    description='REST API for DCNM ACL Manager',
    authorizations=authorizations, root_path=BASE_PATH)

## Fix for Swagger Absolute URLs
@api.documentation
def custom_ui():
    return render_template("swagger-ui.html", title=api.title, specs_url="./swagger.json")

## Flask-Restx
app.config['BUNDLE_ERRORS'] = True

app.config.from_object(__name__)

# enable CORS
CORS(app, supports_credentials=True, resources={r'/*': {'origins': '*'}})

# cookieDomain = app.session_interface.get_cookie_domain(app)
# logging.debug("Cookie Domain: {}".format(cookieDomain))


## Flask-Session
SESSION_TYPE = 'filesystem'

### Setup Session ###
app.secret_key = b'??%_a?d??vX?,'
app.config['SESSION_COOKIE_NAME'] = "dcnm_aclm"

### Allow JS to read session cookie - BAD
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
# app.config['SESSION_COOKIE_SECURE'] = True

app.config['SESSION_FILE_DIR'] = "/var/run/session/"
app.config.from_object(__name__)
Session(app)

def buildAclmFromSession(updateCache = False, clearPending = False):

    ## Build from Session
    logging.debug("[restServer][buildAclmFromSession] Building ACLM from Session: updateCache:{}".format(updateCache))
    logging.debug("[restServer][buildAclmFromSession] Session State: {}".format(session))
    session['UPDATE_CACHE'] = updateCache

    flask_aclm = aclm(**session)

    ## Reset Update Cache
    session['UPDATE_CACHE'] = False

    ## Update JSON Cache
    session['POLICY_CACHE'] = flask_aclm.POLICY_CACHE  # change name to POLICY_CACHE

    ## Update Expiry Timer
    session['DCNM_EXPIRY'] = flask_aclm.DCNM_EXPIRY

    ## Update Fabric Inventory
    session['FABRIC_INVENTORY'] = flask_aclm.FABRIC_INVENTORY

    if clearPending == True:
        session['PENDING'] = {}
    else:
        pendingDict = session.get('PENDING')
        if pendingDict != None and len(pendingDict) > 0:
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

deployStatusResult = api.model('deployStatusResult', {
    'status': fields.String
})

wild_status = fields.Wildcard(fields.Nested(deployStatusResult, skip_none=True))
wild_acl = MyWildcard(fields.Nested(aclModel, skip_none=True))

entryModel = api.model('entryModel', {
    '*': wild_acl
})

policyModel = api.model('policyModel', {
    '*': wild_str
})


deployStatusModel = api.model('deployStatusModel', {
    '*': wild_status
})

aclgModel = api.model('aclgModel', {
    'name': fields.String,
    'hash': fields.String,
    ### Wildcard can't cope with integer keys!!!
    'entries': fields.Nested(entryModel, skip_none=True)
    # 'entries': fields.String
})


# successDeployState = api.model('successDeployState', {
#     'successPolicy': fields.String,
#     'serialNumber': fields.String
# })
#
# failedDeployState = api.model('failedDeployState', {
#     'failedPolicy': fields.String,
#     'serialNumber': fields.String
# })

# deployOuputModel = api.model('deployOuputModel', {
#     'success': fields.List(fields.Nested(successDeployState, required=False, skip_none=True), required=False, skip_none=True),
#     'failed': fields.List(fields.Nested(failedDeployState, required=False, skip_none=True), required=False, skip_none=True)
# })

policyListModel = api.model('policyListModel', {
    'policyList': fields.List(fields.String, skip_none=True),
})

logonModel = api.model('logonModel', {
    'username': fields.String,
    'password': fields.String,
    'server': fields.String
})

logonResponse = api.model('logonResponse', {
    'logonStatus': fields.String,
})

selectFabricModel = api.model('selectFabricModel', {
    'updateCache': fields.Boolean,
    'fabricName': fields.String
})

managedAclModel = api.model('aclmModel', {
    'name': fields.String,
    'description': fields.String,
    'hash': fields.String,
    'status': fields.String,
    'policies': fields.Nested(policyModel, required=False, skip_none=True),
    'acl': fields.Nested(aclgModel, skip_none=True),
    'cli': fields.String,
    'toAttach': fields.List(fields.String, skip_none=True),
    'toDetach': fields.List(fields.String, skip_none=True),
    'toDeploy': fields.List(fields.String, skip_none=True),
    # 'deployOutput': fields.Nested(deployOuputModel, skip_none=True)
    #'deployOutput': fields.List(fields.String, required=False, skip_none=True)
    'deployOutput': fields.Nested(deployStatusModel, required=False, skip_none=True)
})

newAclModel = api.model('newAclModel', {
    'name': fields.String,
    'description': fields.String,
    'hash': fields.String,
    'status': fields.String,
    'acl': fields.Nested(aclgModel, required=False, skip_none=True),
    'cli': fields.String,
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

@app.before_request
def beforeRequest():
    """
    Run before any API request
    - Updates Session information from Cookies variables
    - Updates Session information from Environmental variables
    """
    logging.debug("[beforeRequest] Running Update Request")

    # From http cookies
    parser = reqparse.RequestParser()
    parser.add_argument('username', type=str, default="", location='cookies')
    parser.add_argument('resttoken', type=str, default="", location='cookies')
    args = parser.parse_args()
    logging.debug("[beforeRequest] Parsed Arguments: {}".format(args))
    username = args['username']
    resttoken = args['resttoken']

    ## Temp workaround -- will be set by cookie
    if username == None or username == "":
        session['DCNM_USERNAME'] = "apiuser"


    ## Split resttoken
    if resttoken == None or resttoken !="":
        tokenList = resttoken.split(":")
        session['DCNM_TOKEN'] = tokenList[1] # needed in session?
        logging.debug("[beforeRequest] DCNM_TOKEN: {}".format(session['DCNM_TOKEN']))
        session['DCNM_USERNAME'] = username
        session['DCNM_OFFLOADED'] = True

        if session.get('INITIALISED') == None:
            ## Setup Backend Session
            session['DCNM_PASSWORD'] = None # not required here
            session['DCNM_EXPIRY'] = None # not required here
            session['ACLM_OBJECTS'] = {}
            session['PENDING'] = {}
            session['SELECTED_FABRIC'] = None
            session["FABRIC_INVENTORY"] = None
            session['POLICY_CACHE'] = None
            session['INITIALISED'] = True
            logging.debug("[beforeRequest] New Backend Session: {}".format(session))

    else:
        session['DCNM_TOKEN'] = None
        session['DCNM_OFFLOADED'] = False


    # From Environmental
    session['DCNM_FQDN'] = DCNM_MGMT_VIP

    return


@api.route('/session')
class backendSession(Resource):
    # def post(self):
    #     """
    #     Sets up new backend session with DCNM offloaded frontend cookie information
    #     """
    #     try:
    #         ## Setup backend session information
    #         if session.get('INITIALISED') == None:
    #
    #             session['DCNM_PASSWORD'] = None # not required here
    #             session['DCNM_EXPIRY'] = None # not required here
    #
    #             ## Current Managed ACLM Hash IDs for Fabric
    #             session['ACLM_OBJECTS'] = {}
    #
    #             ## Set Pending ACL Dictionary
    #             session['PENDING'] = {}
    #
    #             ## Set Selected Serial Numbers
    #             session['SELECTED_FABRIC'] = None
    #             session["FABRIC_INVENTORY"] = None
    #             session['POLICY_CACHE'] = None
    #
    #             session['INITIALISED'] = True
    #
    #             logging.debug("[backendSession][post] New Backend Session: {}".format(session))
    #
    #             # return {'logonStatus':'OK'}, 200, {'Access-Control-Allow-Origin': '*'}
    #             return {'newSession':'OK'}
    #
    #     ### Catch All Exceptions
    #     except HTTPException as e:
    #         logging.error("[backendSession][post] Error: {}".format(e))
    #         api.abort(e.code, e.__doc__, status = str(e), statusCode = e.code)
    #     except Exception as e:
    #         logging.error("[backendSession][post] Error: {}".format(e))
    #         api.abort(500, e.__doc__, status = str(e), statusCode = "500")

    @api.doc(security='session')
    def delete(self):
        """
        Clear backend session
        """
        try:
            flask_aclm = buildAclmFromSession(False, True)
            output = flask_aclm.dcnmLogout()
            logging.debug("[backendSession][delete] Output: {}".format(output))

            ## Clear Session
            session.clear()
            logging.debug("[backendSession][delete] Session: {}".format(session))

            return {'deleteSession':'OK'}

        ### Catch All Exceptions
        except HTTPException as e:
            logging.error("[backendSession][post] Error: {}".format(e))
            api.abort(e.status_code, e.__doc__, status = str(e), statusCode = e.status_code)
        except Exception as e:
            logging.error("[backendSession][post] Error: {}".format(e))
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")

### HORRIBLY INSECURE!!!
@api.route('/logon')
class dcnmLogon(Resource, ):
    @api.param('username','DCNM Username', type=str, default="apiuser")
    @api.param('password','DCNM Password', type=str, default="C!sco123")
    #@api.param('server','DCNM Server', type=str, default="10.67.29.26")
    def get(self):
        """
        Sets up Flask session with DCNM session token
        """
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, location='args')
        parser.add_argument('password', type=str, required=True, location='args')
        #parser.add_argument('server', type=str, required=True, location='args')
        args = parser.parse_args()
        logging.debug("[dcnmLogon][get] Parsed Arguments: {}".format(args))
        username = args['username']
        password = args['password']
        #server = args['server']

        session['DCNM_USERNAME'] = username
        session['DCNM_PASSWORD'] = password
        session['DCNM_FQDN'] = DCNM_MGMT_VIP

        flask_aclm =  aclm(**{'DCNM_FQDN':DCNM_MGMT_VIP, 'DCNM_USERNAME':username, 'DCNM_PASSWORD':password})
        flask_aclm.dcnmLogon() # Required to set token?

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

        # return {'logonStatus':'OK'}, 200, {'Access-Control-Allow-Origin': '*'}
        return {'logonStatus':'OK'}

    @api.marshal_with(logonResponse)
    @api.expect(logonModel)
    def post(self):
        """
        Sets up Flask session with DCNM session token
        """
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        parser.add_argument('server', type=str, required=False)
        args = parser.parse_args()
        logging.debug("[dcnmLogon][get] Parsed Arguments: {}".format(args))
        username = args['username']
        password = args['password']
        if args.get('server') == None:
            server = "10.67.29.26"
        else:
            server = args['server']

        session['DCNM_USERNAME'] = username
        session['DCNM_PASSWORD'] = password
        session['DCNM_FQDN'] = server

        flask_aclm =  aclm(**{'DCNM_FQDN':server, 'DCNM_USERNAME':username, 'DCNM_PASSWORD':password})
        flask_aclm.dcnmLogon() # Required to set token?

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
            output = flask_aclm.dcnmLogout()
            logging.debug("[dcnmLogout][get] Output: {}".format(output))

            ## Clear Session
            session.clear()
            logging.debug("[dcnmLogout][get] Session: {}".format(session))

            return {'logoutStatus':'OK'}

        ### Catch All Exception
        except Exception as e:
            logging.error(e)
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")

    def post(self):
        """
        Logout of DCNM
        Clear Flask Session
        Clear Cookie?
        """
        try:
            flask_aclm = buildAclmFromSession(False, True)
            output = flask_aclm.dcnmLogout()
            logging.debug("[dcnmLogout][get] Output: {}".format(output))

            ## Clear Session
            session.clear()
            logging.debug("[dcnmLogout][get] Session: {}".format(session))

            return {'logoutStatus':'OK'}

        ### Catch All Exception
        except Exception as e:
            logging.error(e)
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")

@api.route('/fabric/listFabrics')
class listFabrics(Resource):
    @api.doc(security='session')
    def get(self):
        """
        Returns list of fabrics
        """
        logging.debug("[listFabrics][get] List Fabrics")
        flask_aclm = buildAclmFromSession()
        fabricList = flask_aclm.getFabrics()

        output = []
        for fabric in fabricList:
            entry = {}
            entry['id'] = fabric['id']
            entry['fabricId'] = fabric['fabricId']
            entry['fabricName'] = fabric['fabricName']
            entry['fabricType'] = fabric['fabricType']
            output.append(entry)

        logging.debug("[listFabrics][get] Fabrics: {}".format(output))
        return output


@api.route('/fabric/selectFabric/<string:fabricName>')
class selectFabric(Resource):
    @api.doc(security='session')
    # @api.param('fabricName','Fabric scope for ACLs', type=str, default="DC3")
    @api.param('updateCache','Force update of JSON policies cache', type=bool, default=False)
    def get(self, fabricName):
        """
        Builds Managed ACL Objects for switches in selected fabric and returns dictonary of hash IDs
        """
        parser = reqparse.RequestParser()
        # parser.add_argument('fabricName', required=True, type=str, location='args')
        parser.add_argument('updateCache', type=inputs.boolean, location='args')
        args = parser.parse_args()
        logging.debug("[selectFabric][get] Parsed Arguments: {}".format(args))
        # fabricName = args['fabricName']
        updateCache = args['updateCache']

        # ## Get Currently Selected Switches
        # sessionSerialNumbers = session.get('SELECTED_SERIAL_NUMBERS')
        # logging.debug("[selectFabric][get] Currently Selected Switches: {}".format(sessionSerialNumbers))

        ## Build ACLM
        if session.get('SELECTED_FABRIC') != None and fabricName != session['SELECTED_FABRIC'] and len(session['PENDING']) > 0:
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


        ## Clear ACLM Objects
        session['ACLM_OBJECTS'] = {}
        output = {}

        ## Build default view of ACLM Objects
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

        ## Return Output
        output["acls"] = session['ACLM_OBJECTS']
        output["inventory"] = session['FABRIC_INVENTORY']
        return output

    # @api.doc(security='session')
    # # @api.marshal_with(logonResponse)
    # @api.expect(selectFabricModel)
    # def post(self):
    #     """
    #     Builds Managed ACL Objects for switches in selected fabric and returns dictonary of hash IDs
    #     """
    #     parser = reqparse.RequestParser()
    #     parser.add_argument('fabricName', required=True, type=str)
    #     parser.add_argument('updateCache', type=inputs.boolean)
    #     args = parser.parse_args()
    #     logging.debug("[selectFabric][post] Parsed Arguments: {}".format(args))
    #     fabricName = args['fabricName']
    #     updateCache = args['updateCache']
    #
    #     ## Build ACLM
    #     if fabricName != session['SELECTED_FABRIC'] and len(session['PENDING']) > 0:
    #         clearPending = True
    #         logging.warning("[selectFabric][post] New fabric selected clearing pending changes.")
    #     else:
    #         clearPending = False
    #
    #     ## Set Selected Fabric Name
    #     session['SELECTED_FABRIC'] = fabricName
    #     session['ACLM_OBJECTS'] = {}
    #     flask_aclm = buildAclmFromSession(updateCache, clearPending)
    #
    #     output = {}
    #
    #     ## Build default view of ACLM Objects
    #     keylist = list(flask_aclm.ACLS.keys())
    #     for key in keylist:
    #         logging.debug("[selectFabric][get] Processing Key: {}".format(key))
    #         managedACL = flask_aclm.ACLS[key]
    #         session['ACLM_OBJECTS'][key] = {
    #             'name': managedACL.name,
    #             'hash': key,
    #             'status': managedACL.status,
    #             # 'toAttach': list(postUpdateAcl.toAttach),
    #             # 'toDetach': list(postUpdateAcl.toDetach),
    #             'toDeploy': list(managedACL.toDeploy),
    #             }
    #
    #     ## Return Output
    #     output["acls"] = session['ACLM_OBJECTS']
    #     output["inventory"] = session['FABRIC_INVENTORY']
    #     return output

@api.route('/aclm/')
@api.param('autoDeploy','Automatically deploy new policies', type=bool, default=False)
class newAclm(Resource):
    @api.doc(security='session')
    @api.marshal_with(newAclModel)
    @api.expect(newAclModel)
    @api.param('update','Update by CLI or JSON', type=str)
    def post(self):
        """
        Create New Managed ACL
        """
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('update', type=str, location='args')
            args = parser.parse_args()
            update = args['update']

            ## Build ACLM
            flask_aclm = buildAclmFromSession()
            logging.info("[newAclm][post] Create New Managed ACL")
            logging.debug("[newAclm][post] Payload: {}".format(api.payload))

            if update == "cli":
                managedACL = flask_aclm.createAclmFromCli(api.payload)
            else:
                ## Assume JSON
                managedACL = flask_aclm.createAclmFromJson(api.payload)

            session['PENDING'][managedACL.hash] = managedACL.toDict()
            logging.debug("[newAclm][post] Current Pending ACLs in Session: {}".format(session['PENDING']))

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
    @api.param('update','Update by CLI or JSON', type=str)
    def put(self, hash):
        """
        Update Managed ACL for selected hash ID
        """
        try:
            ## Get Args
            parser = reqparse.RequestParser()
            parser.add_argument('autoDeploy', type=inputs.boolean, location='args')
            parser.add_argument('update', type=str, location='args')
            args = parser.parse_args()
            autoDeploy = args['autoDeploy']
            update = args['update']


            ## Build ACLM
            flask_aclm = buildAclmFromSession()

            logging.info("[aclmByHash][put] Update Managed ACL. Hash:{}".format(hash))
            logging.debug("[aclmByHash][put] Payload: {}".format(api.payload))

            ## Get Existing Managed ACL Object
            managedACL = flask_aclm.ACLS[hash]
            logging.debug("[aclmByHash][put] Initial ACL Object: {}".format(managedACL))

            if update == "cli":
                updatedACL = managedACL.updateFromCli(api.payload)
            else:
                ## Assume JSON
                updatedACL = managedACL.updateFromJson(api.payload)

            ## Get Updated Hash
            newHash = updatedACL['acl']['hash']

            ## Check if policy description changed
            if managedACL.description != updatedACL['description']:
                forceUpdate = True
            else:
                forceUpdate = False

            ## Update Policies in DCNM
            if len(managedACL.policies) > 0:
                flask_aclm.updatePolicies(managedACL, forceUpdate)
            elif managedACL.status == "NotApplied" and len(managedACL.toAttach) > 0:
                ## New ACLM - waiting to attach!
                flask_aclm.updatePolicies(managedACL, forceUpdate)
                ## Remove from Pending if now Applied
                if managedACL.status == "Applied":
                    session['PENDING'].pop(hash)
            else:
                ### Assume Pending State - Update Pending
                session['PENDING'].pop(hash)
                session['PENDING'][newHash] = updatedACL

            ## Check now NotApplied
            if len(managedACL.policies) == 0:
                logging.warning("[aclmByHash][put] No switches attached to ACL.  This ACL will be moved to pending")
                managedACL.status = "NotApplied"
                session['PENDING'][newHash] = managedACL.toDict()

            ## Copy Old Hash to New Hash for toDeploy
            if hash != newHash:
                del session['ACLM_OBJECTS'][hash]
                session['ACLM_OBJECTS'][newHash] = {
                    'name': updatedACL['name'],
                    'description': updatedACL['description'],
                    'hash': newHash,
                    'status': updatedACL['status'],
                    'toDeploy': list(managedACL.toDeploy),
                }

            ## Clear Cache & Rebuild
            flask_aclm = buildAclmFromSession(True, False)

            ## Get Updated Hash
            postUpdateAcl = flask_aclm.ACLS[newHash]

            ## AutoDeploy
            deployOutput = None
            if autoDeploy and len(postUpdateAcl.toDeploy) > 0:
                deployOutput = flask_aclm.deployPolicies(postUpdateAcl)

            # ## Remove Pending ACL
            # if managedACL.hash in list(session['PENDING'].keys()):
            #     session['PENDING'].pop(managedACL.hash)

            # ## Rebuild Session ACLM Objects
            # keylist = list(flask_aclm.ACLS.keys())
            # for key in keylist:
            #     logging.debug("[aclmByHash][put] Rebuilding Session ACLM Objects: {}".format(key))
            #     managedACL = flask_aclm.ACLS[key]
            #     session['ACLM_OBJECTS'][key] = {
            #      'name': managedACL.name,
            #      'hash': key,
            #      'status': managedACL.status,
            #      # 'toAttach': list(postUpdateAcl.toAttach),
            #      # 'toDetach': list(postUpdateAcl.toDetach),
            #      'toDeploy': list(managedACL.toDeploy),
            #      }

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


@api.route('/aclm/<string:hash>/deploy')
class deployAclmByHash(Resource):
    @api.doc(security='session')
    @api.marshal_with(managedAclModel)
    # @api.expect(managedAclModel)
    # @api.param('autoDeploy','Automatically deploy updated policies', type=bool, default=False)
    # @api.param('update','Update by CLI or JSON', type=str)
    def post(self, hash):
        """
        Deploy policies for ACL for selected hash ID
        """
        try:
            # ## Get Args
            # parser = reqparse.RequestParser()
            # parser.add_argument('autoDeploy', type=inputs.boolean, location='args')
            # parser.add_argument('update', type=str, location='args')
            # args = parser.parse_args()
            # autoDeploy = args['autoDeploy']
            # update = args['update']

            ## Build ACLM
            flask_aclm = buildAclmFromSession()

            # logging.info("[deployAclmByHash][post] Update Managed ACL. Hash:{}".format(hash))
            # logging.debug("[deployAclmByHash][post] Payload: {}".format(api.payload))

            ## Get Existing Managed ACL Object
            managedACL = flask_aclm.ACLS[hash]
            logging.debug("[deployAclmByHash][post] Initial ACL Object: {}".format(managedACL))
            logging.debug("[deployAclmByHash][post] toDeploy: {}".format(managedACL.toDeploy))

            deployOutput = flask_aclm.deployPolicies(managedACL)

            ## Remove Pending ACL
            if managedACL.hash in list(session['PENDING'].keys()):
                session['PENDING'].pop(managedACL.hash)

            ## Rebuild Session ACLM Objects
            session['ACLM_OBJECTS'] = {}
            keylist = list(flask_aclm.ACLS.keys())
            for key in keylist:
                logging.debug("[deployAclmByHash][put] Rebuilding Session ACLM Objects: {}".format(key))
                managedACL = flask_aclm.ACLS[key]
                session['ACLM_OBJECTS'][key] = {
                 'toDeploy': list(managedACL.toDeploy),
                 }

            ### ACLM Objects
            logging.debug("[deployAclmByHash][put] Updated ACLM Object: {}".format(session['ACLM_OBJECTS']))

            ## Clear Cache
            flask_aclm = buildAclmFromSession(True)

            ## Get Updated Hash
            postUpdateAcl = flask_aclm.ACLS[hash]
            output = postUpdateAcl.toDict()

            output['deployOutput'] = deployOutput

            # ## Process Deploy Output
            # output['deployOutput'] = {
            # 'success': [],
            # 'failed': []
            # }
            # for item in deployOutput:
            #     if item.get("failedPTIList"):
            #         failedPolicy = item.get("failedPTIList")
            #         serialNumber = item.get("switchSN")
            #         output['deployOutput']['failed'].append({'failedPolicy': failedPolicy, 'serialNumber': serialNumber})
            #     elif item.get("successPTIList"):
            #         successPolicy = item.get("successPTIList")
            #         serialNumber = item.get("switchSN")
            #         output['deployOutput']['success'].append({'successPolicy': successPolicy, 'serialNumber': serialNumber})

            # output['deployOutput'] = deployOutput
            logging.debug("[deployAclmByHash][post] Post Update ACL Object: {}".format(output))
            return output

        except Exception as e:
            logging.error("[deployAclmByHash][post] Error: {}".format(e))
            api.abort(500, e.__doc__, status = str(e), statusCode = "500")


# @api.route('/aclm/deployPolicies')
# # @api.param('autoDeploy','Automatically deploy new policies', type=bool, default=False)
# class deployPolicies(Resource):
#     @api.doc(security='session')
#     # @api.marshal_with(newAclModel)
#     # @api.expect(policyListModel)
#     def post(self):
#         """
#         Create New Managed ACL
#         """
#         try:
#             parser = reqparse.RequestParser()
#             parser.add_argument('policyList', required=True, type=str) # parser.add_argument('name', action='append')
#             args = parser.parse_args()
#             logging.debug("[deployPolicies][post] Parsed Arguments: {}".format(args))
#             policyList = args['policyList']
#
#             ## Build ACLM
#             flask_aclm = buildAclmFromSession()
#
#             flask_aclm.deployPolicies(managedACL)
#
#
#             # logging.info("[newAclm][post] Create New Managed ACL")
#             # logging.debug("[newAclm][post] Payload: {}".format(api.payload))
#
#
#             # managedACL = flask_aclm.createAclm(api.payload)
#
#             ### Add to Session?
#             # if session.get('PENDING') == None:
#             #     session['PENDING'] = []
#             # elif type(session['PENDING']) != type(list()):
#             #     session['PENDING'] = []
#
#             session['PENDING'][managedACL.hash] = managedACL.toDict()
#             logging.debug("[newAclm][post] Current Session Pending: {}".format(session['PENDING']))
#
#             # ## Update Session ACLM Dict
#             # session['ACLM_OBJECTS'][newHash] = {
#             #     'name': postUpdateAcl.name,
#             #     'hash': newHash,
#             #     'status': postUpdateAcl.status,
#             #     # 'toAttach': list(postUpdateAcl.toAttach),
#             #     # 'toDetach': list(postUpdateAcl.toDetach),
#             #     'toDeploy': list(postUpdateAcl.toDeploy),
#             #     }
#
#             return managedACL.toDict()
#
#         except Exception as e:
#             logging.error("[newAclm][post] Error: {}".format(e))
#             api.abort(500, e.__doc__, status = str(e), statusCode = "500")

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
