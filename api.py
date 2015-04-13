from flask import Flask
from flask.ext import restful
from flask.ext.restful import reqparse
from porc import Client
import hashlib, uuid

app = Flask(__name__)
api = restful.Api(app)

DB_API_KEY = open('orchestrateKey.txt','r')
DB_API_KEY = DB_API_KEY.read()
db = Client(DB_API_KEY)

class Keychain:
    @staticmethod
    def create_user_key(username):
        key = str(uuid.uuid4())
        response = db.put('APIkeys',key,{
            "key": key,
            "username": username,
            "type": "user"
        })
        response.raise_for_status()
        
        return key

    def get_user_api_key(username):
        pages = db.search('APIkeys',username)
        keys = pages.all()
        return keys[0]

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
        pages = db.search('users','value.email:'+args['email'])

        if len(pages.all()) > 0:
             return {"message":"Email already in use","code":"email_in_use"}, 400

        user = db.get('users', args['username'])
        try:
            #try getting a user with that username. If there is no exception, username exists
            user.raise_for_status()
            return {"message":"Username already in use","code":"username_in_use"}, 400
        except Exception, e:
            pass

    	# TODO: Check that email is valid. Send email and validate
        salt = uuid.uuid4().hex
        hashed_password = hashlib.sha512(salt + args['password']).hexdigest()
        response = db.put('users', args['username'], {
    		"name": args['username'],
    		"password": hashed_password,
            "salt": salt,
    		"email": args['email']
    	})

    	try:
            response.raise_for_status()
        except Exception, e:
            return {"message":"Trouble adding user to database","code":"db_problem"}, 500

        api_key = Keychain.create_user_key(args['username'])

    	return {"username":args['username'],"api_key":api_key}, 201

api.add_resource(UserAPI, '/v0/users')

if __name__ == '__main__':
    app.run(debug=True)