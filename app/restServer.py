import logging
logging.basicConfig(level=logging.DEBUG)
# from aclm import aclm

#from datetime import datetime
from flask import Flask
from flask_restx import Resource, Api, reqparse # fields,

from aclm import aclm

app = Flask(__name__)
api = Api(app, version='1.0', title='ACL Manager REST API',
    description='REST API for DCNM ACL Manager',)

### Setup Session ###

### Build/Load ACLM Object ###
flask_aclm =  aclm()


@api.route('/policy/policyListBySwitches')
@api.param('serialNumbers','Comma separated list of serial numbers')
class getPolicyListBySwitches(Resource):
    #@api.marshal_with(serialNumbers, as_list=True)
    def get(self):
        # FDO22192XCF,FDO21521S70
        parser = reqparse.RequestParser()
        # Look only in the querystring
        parser.add_argument('serialNumbers', type=str, location='args', action='split')
        args = parser.parse_args()
        logging.debug("Parsed Arguments: {}".format(args))

        serialNumberList = args['serialNumbers']
        try:
            jsonList = flask_aclm.getPolicyListBySwitches(serialNumberList)
        except NewConnectionError as e:
            logging.error(e)
            api.abort(500, e.__doc__, status = "Connection Error", statusCode = "500")
        except Exception as e:
            logging.error(e)
            api.abort(400, e.__doc__, status = "Invalid Argument", statusCode = "400")

        return jsonList

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
