from authlib.flask.oauth2 import current_token
from flask import (
    Blueprint, request, Response, redirect, session, render_template, url_for, jsonify)

import json
from scitoken.SciTokenServer import SciTokenServer, TokenManager, SciTokenEnforcer
from scitoken.oauth2 import get_client
from scitoken.models import db, User, OAuth2Client
from scitoken.resource import require_oauth




# TODO : Give thoughts about making these thread safe
scitokenSrv = SciTokenServer(keygen_method=1, ref_token_url='https://127.0.0.1:4005/oauth/ref_token_validate')
scitokenEnf = SciTokenEnforcer()
scitokenTM = TokenManager()

scitoken_bp = Blueprint('scitoken', __name__)
scitoken_bp_tm = Blueprint('scitokentm', __name__)



##########################################
#####       TOKEN MANAGER
##########################################
@scitoken_bp_tm.route('/oauth2RefreshToken', methods=['GET', 'POST'])
def generateOAuth2():
    '''
    This endpoint follows the Authorization Code flow of OAuth2 to obtain a refresh token.
    The OAuth2 server should be provided this endpoint for the call back during client registration
    Note : See the YAML file for more details
    :param:  str userid :  The identifier for the user for which the refresh token will be created.
    :param:  str oauth2_srvname :  Name of the particular OAuth2 service (e.g. "Local", "Twitter") to
                                      identify the client.
    :param:  str redirect_uri : Callback URI for the OAuth2 client, given during registration.
    :param:  str authz_code : Authorization code returned by the OAuth2 server after the user consent.
    :return: Refresh token
    :rtype: str
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
        session.pop('consent')  # del session['consent']
        authz_code = request.form['code'] if request.method == 'POST' else request.args.get('code')
        # this calls /auth/token
        # oAuthsession = OAuth2Session(client_id=client_id, client_secret=client_secret, scope=scope)
        # token = oAuthsession.fetch_access_token(OAUTH2_REFTOKEN_URL, code=request.args.get('code'))
        client = get_client(session['oauth2_srvname'])
        token = client.fetch_access_token(session['redirect_uri'], code=authz_code,
                                          state=session['state'], verify=False) #TODO verify=True for certificate validation
        return scitokenTM.addRefreshToken(session['username'],refresh_token=json.dumps(token['refresh_token']),
                                                          scope=json.dumps(token['scope']),
                                                          access_token=json.dumps(token['access_token']),
                                                          expires_in=json.dumps(token['expires_in']))
    # return redirect(url_for('scitoken.refreshTokenForm', refresh_token=str(token['refresh_token'])))



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
@scitoken_bp.route('/scitokens', methods=['POST'])
def generateAccessSciToken():
    '''
    :param: str paren_token : Parent token for the scitoken to be generated
    :param: str refresh_token : Refresh token that will be validated/used to obtain a refresh token
    :return:  scitoken
    :rtype: str
    '''
    token = scitokenSrv.generate_scitoken(request.form.get('parent_token', None), request.form.get('refresh_token', None))
    #return Response('<p>' + str(token.serialize(issuer='local')) + '</p>')
    return token.serialize(issuer='local')
    #return token.serialize(issuer = "local")


@scitoken_bp.route('/resource', methods=['GET'])
def verifyToken(token, action, resource, issuer):
    scitokenEnf.generateEnforcer()
    return scitokenEnf.enforceToken(request.args.get('token'), request.args.get('act'), request.args.get('id'))



@scitoken_bp.route('/scitokensval', methods=['POST'])
def validateToken():
    return scitokenSrv.validate_token(request.form.get('token'))



# handle login failed --> To be fixed, this is not yet ready...
@scitoken_bp.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')



@scitoken_bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)



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


# This code has been taken from here : https://github.com/authlib/example-oauth2-server
@scitoken_bp.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['userid'] = user.id
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)


@scitoken_bp.route('/logout')
def logOut():
    del session['userid']
    return redirect('/')


@scitoken_bp.route('/create_oauth2_client', methods=['GET', 'POST'])
def createOAuth2client():
    return None



# @scitoken_bp_tm.route('/oauth2Form', methods=['GET'])
# def codeForm():
#     return Response('''
#         <form action="'''
#            + 'http://127.0.0.1:4006' + url_for('.generateOAuth2') +
#         '''" method="post">
#             <p><input type=text name=username value="aliveli">
#             <p><select name="oauth2_srvname">
#                     <option selected="selected">Local</option>
#                     <option>Twitter (Not working)</option>
#                 </select></p>
#             <p><input type=text name=redirect_uri value="'''
#            + 'http://127.0.0.1:4006' + url_for('.generateOAuth2') +
#         '''">
#             <p><input type=text name=authz_code value="">
#             <p><input type=submit value=submit>
#         </form>
#     ''')



# @scitoken_bp.route('/scitokenForm', methods=['GET'])
# def refreshTokenForm():
#     return Response('''
#         <form action="'''
#         + 'http://127.0.0.1:4006' + url_for('.generateAccessSciToken') +
#         '''" method="post">
#             <p><input type=text name=refresh_token value="">
#             <p><input type=submit value=submit>
#         </form>
#     ''')

@scitoken_bp.route('/oauth2Form', methods=['GET'])
def refresh_token_form():
    return render_template('refresh_token_form.html')

@scitoken_bp.route('/scitokenForm', methods=['GET'])
def scitoken_form():
    return render_template('scitoken_form.html')