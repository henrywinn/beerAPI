from flask import Flask
from flask.ext import restful
from flask.ext.restful import reqparse
from porc import Client

app = Flask(__name__)
api = restful.Api(app)

db = Client("9e085038-7a3f-436d-9f30-b9338de315f1")

# Handler for creating new user
class UserAPI(restful.Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('username', type = str, required = True,
            help = 'No username provided')
        self.reqparse.add_argument('email', type = str, required = True,
        	help = 'No email provided')
        self.reqparse.add_argument('password', type = str, required = True,
        	help = 'No password provided')
        super(UserAPI, self).__init__()

    def post(self):
    	args = self.reqparse.parse_args()
    	return args

api.add_resource(UserAPI, '/v0/users')

if __name__ == '__main__':
    app.run(debug=True)