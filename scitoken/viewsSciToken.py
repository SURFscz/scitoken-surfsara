from authlib.flask.oauth2 import current_token
from flask import (
    Blueprint, request, Response, redirect, session, render_template, url_for, jsonify, make_response)
import json
from scitoken.SciTokenServer import SciTokenServer, TokenManager, SciTokenEnforcer
from scitoken.oauth2 import get_client
from scitoken.models import db, User, OAuth2Client


# DEMO Related imports
from scitoken.resource import require_oauth
from flask_login import login_required, login_user, logout_user
from scitoken.demo import login_manager, bcrypt




ISSUER = 'https://localhost:4005'
scitokenSrv = SciTokenServer(keygen_method=1, ref_token_url='https://127.0.0.1:4005/oauth/ref_token_validate', issuer=ISSUER)
scitokenEnf = SciTokenEnforcer()
scitokenTM = TokenManager()

scitoken_bp = Blueprint('scitoken', __name__)
scitoken_bp_tm = Blueprint('scitokentm', __name__)



##########################################
#####       SCITOKEN MANAGER
##########################################
def __get_refresh_token(authz_code, username, oauth2_srvname, redirect_uri, state):
    '''
    This is an auxiliary method for obtaining an access/refresh token according to Authorization Code flow.

    :param str authz_code: Authorization code
    :param str username: The user identifier
    :param str oauth2_srvname: The identifier for the OAuth2 service
    :param str redirect_uri: The callback URI
    :param state: State parameter for the OAuth2 server
    :return: Refresh token, strips away the access token.
    :rtype: str
    '''
    # oAuthsession = OAuth2Session(client_id=client_id, client_secret=client_secret, scope=scope)
    # token = oAuthsession.fetch_access_token(OAUTH2_REFTOKEN_URL, code=request.args.get('code'))
    client = get_client(oauth2_srvname)
    token = client.fetch_access_token(redirect_uri, code=authz_code, state=state, verify=False)
    scitokenTM.addRefreshToken(username=username,
                               refresh_token=json.dumps(token['refresh_token']),
                               scope=json.dumps(token['scope']),
                               access_token=json.dumps(token['access_token']),
                               expires_in=json.dumps(token['expires_in']))
    return token['refresh_token']



@scitoken_bp_tm.route('/oauth2RefreshToken', methods=['GET', 'POST'])
def generateOAuth2():
    ''' This endpoint follows the Authorization Code flow of OAuth2 to obtain a refresh token.
    The OAuth2 server should be provided this endpoint for the call back during client registration
    Note : See the YAML file for more details

    :param:  str username :  The identifier for the user for which the refresh token will be created.
    :param:  str oauth2_srvname :  Name of the particular OAuth2 service (e.g. "Local", "Twitter") to
                                      identify the client.
    :param:  str redirect_uri : Callback URI for the OAuth2 client, given during registration.
    :param:  str authz_code : Authorization code returned by the OAuth2 server after the user consent.
    :return: Refresh token
    :rtype: str (HTTP Response)
    '''
    if session.get('consent') is None: #this calls /auth/authorize
        session['consent'] = True
        if request.method == 'GET':
            session['username'] = request.args.get('username')
            session['redirect_uri'] = request.args.get('redirect_uri')
            session['oauth2_srvname'] = request.args.get('oauth2_srvname')
            session['state'] = None if 'state' in request.args else request.args.get('state')
        elif request.method == 'POST':
            session['username'] = request.form['username']
            session['redirect_uri'] = request.form['redirect_uri']
            session['oauth2_srvname'] = request.form['oauth2_srvname']
            session['state'] = request.form.get('state', None)
        client = get_client(session['oauth2_srvname'])
        uri, state = client.generate_authorize_redirect(session['redirect_uri'])
        uri = uri + '&username='+session['username']
        return redirect(uri, code=303)
    else:
        # session.pop('consent')  # del session['consent']
        authz_code = request.form['code'] if request.method == 'POST' else request.args.get('code')
        return jsonify(refresh_token=__get_refresh_token(authz_code=authz_code,
                                 oauth2_srvname = session['oauth2_srvname'],
                                 username= session['username'],
                                 redirect_uri=session['redirect_uri'],
                                 state=session['state']))
        #return redirect(session['redirect_uri'], refresh_token=str(token['refresh_token']))




    # The client send a POST request with:
    # "grant_type" : "refresh_token"
    # "refresh_token" : the original refresh token
    # "client_id" : the ID of the client
    # "client_secret" : client's secret
    # "scope" :  A space-delimited list of requested scope permissions
    # def generateSciRefreshToken(self, refresh_token, client_id, client_secret, scope, authz_code, id_token=None):
    #     session = OAuth2Session(client_id, client_secret, scope=scope)
    #     r_token = scitokens.generate("refresh_token", refresh_token, client_id, client_secret, scope)
    #     access_token_url = 'https://127.0.0.1:4005/oauth/token'
    #     token = session.fetch_access_token(access_token_url, code=authz_code)
    #     return token['refresh_token']



##########################################
#####       SCITOKEN SERVER
##########################################
def __generate_scitoken(ptoken = None, rtoken = None, claims= None, scitokenissuer=ISSUER):
    '''    This is an auxiliary method for generating a scitoken.

    :param str ptoken: Parent token for the newly generated Scitoken
    :param str rtoken: Refresh token used to obtain scitoken
    :param set claims: Set of claims that will be added (i.e. update) to the scitoken
    :return: Scitoken in serialized form
    :rtype: str
    '''
    scitoken = scitokenSrv.generate_scitoken(parent_token = ptoken,
                                          refresh_token = rtoken,
                                          claims = claims)
    return scitoken.serialize(issuer=scitokenissuer)


@scitoken_bp.route('/scitokens', methods=['POST'])
def generateAccessSciToken():
    ''' Generates a scitoken

    :param: str paren_token : Parent token for the scitoken to be generated
    :param: str refresh_token : Refresh token that will be validated/used to obtain a refresh token
    :param set claims: Set of claims that will be added (i.e. update) to the scitoken
    :return:  Serialized Scitoken in JSON format
    :rtype: str (HTTP Response)
    '''
    scitoken = __generate_scitoken(ptoken = request.form.get('parent_token', None),
                                   rtoken = request.form.get('refresh_token', None),
                                   claims = request.form.get('claims', None),
                                   issuer = request.form.get('issuer', None))
    token = scitokenSrv.deserialize(scitoken)
    return make_response(json.dumps(token.__dict__), 200)




@scitoken_bp.route('/resource', methods=['POST'])
def enforceToken():
    ''' Enforcement method for scitoken-based accesses

    :param: str token : Scitoken used for access
    :param: str act : Action to be performed {read,write,execute,queue}
    :param: str id : Resource identifier
    :return: True/False
    :rtype: bool (HTTP Response)
    '''
    scitokenEnf.generateEnforcer(issuer=ISSUER)
    if request.method == 'GET':
        result = scitokenEnf.enforceToken(request.args.get('token'), request.args.get('act'), request.args.get('id'), scitokenSrv.public_key_pem)
    elif request.method == 'POST':
        result = scitokenEnf.enforceToken(request.form['token'], request.form['act'], request.form['id'], scitokenSrv.public_key_pem)
    return make_response(json.dumps('result :' + str(result), 200))



@scitoken_bp.route('/scitokensval', methods=['POST'])
def validateToken():
    return make_response(json.dumps('result :' + str(scitokenSrv.validate_token(request.form.get('token'))), 200))




# handle login failed --> To be fixed, this is not yet ready...
@scitoken_bp.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')









######################
##### DEMO CODES #####
######################

@scitoken_bp.route('/hello', methods=['GET'])
def index():
    return "<h2>Welcome to SciToken Demo</h2>"


def current_user():
    if 'userid' in session:
        uid = session['userid']
        return User.query.get(uid)
    return None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@scitoken_bp.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    passwd = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, password_hash=bcrypt.generate_password_hash(passwd))
        db.session.add(user)
        db.session.commit()
        login_user(user)
    return redirect('/')


# This code has been taken from here : https://github.com/authlib/example-oauth2-server
@scitoken_bp.route('/', methods=['GET', 'POST'])
@login_required
def home():
    user = current_user()
    rtoken=None
    scitoken = None
    if user:
        clientlist = OAuth2Client.query.filter_by(user_id=user.username).all()
        if request.method == 'GET' and 'code' in request.args:
            rtoken = __get_refresh_token(authz_code=request.args.get('code'),
                                oauth2_srvname=session['oauth2_srvname'],
                                username=session['username'],
                                redirect_uri=session['redirect_uri'],
                                state=session['state'])
        elif request.method=='POST' and 'code'  in request.form:
            rtoken = __get_refresh_token(authz_code=request.form['code'],
                                         oauth2_srvname=session['oauth2_srvname'],
                                         username=session['username'],
                                         redirect_uri=session['redirect_uri'],
                                         state=session['state'])
        if request.method=='POST' and 'refresh_token' in request.form:
            claims = {'scp': [request.form['scope']]}
            scitoken=__generate_scitoken(ptoken=None, rtoken=request.form['refresh_token'], claims=claims)
            #scitoken=json.dumps(scitokenSrv.deserialize(scitoken_obj).__dict__)
    else:
        return redirect(url_for('scitoken.login'))
    return render_template('home.html', user=user,
                                        clients=clientlist,
                                        refresh_token=rtoken,
                                        scitoken=scitoken)


@scitoken_bp.route('/logout')
def logOut():
    user = current_user()
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    return redirect('/')


@scitoken_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user:
            if user.check_password(request.form['password']):
                user.authenticated = True
                session['userid'] = user.username
                login_user(user)
    return redirect('/')


@scitoken_bp.route('/create_oauth2_client', methods=['GET', 'POST'])
def createOAuth2client():
    return None


@scitoken_bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    return jsonify(username=user.username)




######################
##### ADDITIONAL FORMS #####
######################

@scitoken_bp.route('/oauth2Form', methods=['GET'])
def refresh_token_form():
    user = current_user()
    return render_template('refresh_token_form.html', user=user)

@scitoken_bp.route('/scitokenForm', methods=['GET'])
def scitoken_form():
    return render_template('scitoken_form.html')

@scitoken_bp.route('/registrationForm', methods=['GET'])
def registration_form():

    return render_template('register.html')