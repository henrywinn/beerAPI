from flask import Flask, jsonify, abort, make_response, request
from flask.ext import restful
from flask.ext.restful import reqparse
from flask.ext.httpauth import HTTPBasicAuth
from porc import Client
import hashlib, uuid, iso8601, pytz
from datetime import datetime, timedelta

app = Flask(__name__)
api = restful.Api(app)
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username,password):
    # This logic is only run when api key is being recalled
    # through /tokens (see: GetToken.get())
    if password != '':
        if request.path != '/v0/tokens': return False
        user = db.get('users', username)
        user.raise_for_status()

        if user['salt'] != None:
            hashed_password = hashlib.sha512(user['salt'] + password).hexdigest()
            return hashed_password == user['password']
        else:
            return False
    # In every instance of basic auth, besides aforementioned,
    # an authtoken will be passed as the username. Check to
    # make sure that provided token is valid
    else:
        return Keychain.validate_api_key(username)


@auth.error_handler
def unauthorized():
    #TODO describe the issue better (invalid token, etc)
    return make_response(jsonify({'message': 'Unauthorized access','code': 'unauthorized_access'}), 401)

DB_API_KEY = open('orchestrateKey.txt','r')
DB_API_KEY = DB_API_KEY.read()
db = Client(DB_API_KEY)

class Keychain:
    @staticmethod
    def create_user_key(username, expire_in=timedelta(days=7)):
        expiration = datetime.now() + expire_in
        key = str(uuid.uuid4())
        while len(db.search('APIkeys', 'key:"'+key+'"').all()) > 0:       # test that key is unique,
            key = str(uuid.uuid4())                                 # replace if it is
        response = db.put('APIkeys',key,{
            "key": key,
            "username": username,
            "type": "user",
            "expires": expiration.isoformat()
        })
        response.raise_for_status()

        return (key, expiration.isoformat())

    @staticmethod
    def get_user_api_key(username):
        pages = db.search('APIkeys',username)
        keys = pages.all()
        #TODO access these values in a better way
        return (keys[0]['value']['key'], keys[0]['value']['expires'])

    #return True if valid, False if not
    @staticmethod
    def validate_api_key(key):
        result = db.get('APIkeys', 'username:"'+key+'"')
        try:
            result.raise_for_status()
            pass
        except Exception, e:
            return False

        utc=pytz.UTC
        expiration = iso8601.parse_date(result['expires'])
        now = utc.localize(datetime.now())
        if expiration > now:
            return True
        else:
            return False


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

        if len(db.search('users','value.email:'+args['email']).all()) > 0:
             return {"message":"Email already in use","code":"email_in_use"}, 400

        user = db.get('users', args['username'])
        try:
            # Try getting a user with that username.
            # Exception == no user with that username exists
            # so if there is no exception return 400
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

        api_key,expiration = Keychain.create_user_key(args['username'])

    	return {"username":args['username'],"api_key":api_key,"expires":expiration}, 201

# Used when getting a user api token
class GetToken(restful.Resource):
    decorators = [auth.login_required]
    def get(self):
        api_key,expiration = Keychain.get_user_api_key(auth.username())
        return {"username":auth.username(),"api_key":api_key,"expires":expiration}

class Beer(restful.Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type = str, required = True,
            help = 'No name provided')
        self.reqparse.add_argument('abv', type = float, required = False,)
        self.reqparse.add_argument('ibu', type = int, required = False,)
        self.reqparse.add_argument('style', type = str, required = False,)
        self.reqparse.add_argument('description', type = str, required = False,)
        self.reqparse.add_argument('brewery', type = str, required = False,)
        super(Beer, self).__init__()


    def get(self):
        #TODO implement beer retrieval
        return {'message': 'beer'}

    def post(self):
        decorators = [auth.login_required]
        args = self.reqparse.parse_args()

        unique_id = str(uuid.uuid4())
        while len(db.search('APIkeys', '@path.key:"'+unique_id+'"').all()) > 0:       # test that key is unique,
            unique_id = str(uuid.uuid4())                                            # replace if it is

        new_beer = {"unique_id":unique_id}
        new_beer['name'] = args['name']
        if 'abv' in args:
            new_beer['abv'] = args['abv']
        if 'ibu' in args:
            new_beer['ibu'] = args['ibu']
        if 'style' in args:
            new_beer['style'] = args['style']
        if 'description' in args:
            new_beer['description'] = args['description']
        if 'brewery' in args:
            new_beer['brewery'] = args['brewery']
        response = db.put('beers',unique_id,new_beer)
        return new_beer


api.add_resource(UserAPI, '/v0/users')
api.add_resource(GetToken, '/v0/tokens')
api.add_resource(Beer, '/v0/beers')

if __name__ == '__main__':
    app.run(debug=True)
