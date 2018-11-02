from authlib.flask.oauth2 import current_token
from flask import (
    Blueprint, request, Response, redirect, session, render_template, url_for, current_app)

import json
from scitoken.SciTokenClass import SciTokenClass, TokenManager
from scitoken.oauth2 import get_client
from scitoken.models import OAuth2RefreshToken, db, User, OAuth2Client

scitokenins = SciTokenClass(1)
scitokenTM = TokenManager()

scitoken_bp = Blueprint('scitoken', __name__)


@scitoken_bp.route('/oauth2RefreshToken', methods=['GET', 'POST'])
def generateOAuth2():
    '''
    This endpoint follows the Authorization Code flow of OAuth2 to obtain a refresh token.
    The OAuth2 server should be provided this endpoint for the call back during client registration
    Note : See the YAML file for more details
    :parameter:  str userid :  The identifier for the user for which the refresh token will be created.
    :parameter:  str oauth2_srvname :  Name of the particular OAuth2 service (e.g. "Local", "Twitter") to
                                      identify the client.
    :parameter:  str redirect_uri : : Callback URI for the OAuth2 client, given during registration.
    :parameter:  str authz_code : : Authorization code returned by the OAuth2 server after the user consent.
    :return: Refresh token
    :rtype: str
    '''
    if session.get('consent') is None: #this calls /auth/authorize
        session['consent'] = True
        if request.method == 'GET':
            session['username'] = request.args.get('username')
            session['redirect_uri'] = request.args.get('redirect_uri')
            session['oauth2_srvname'] = request.args.get('oauth2_srvname')
        elif request.method == 'POST':
            session['username'] = request.form['username']
            session['redirect_uri'] = request.form['redirect_uri']
            session['oauth2_srvname'] = request.form['oauth2_srvname']
        client = get_client(session['oauth2_srvname'])
        uri, state = client.generate_authorize_redirect(session['redirect_uri'])
        uri = uri + '&username='+session['username']
        return redirect(uri, code=303)
    session.pop('consent')    #del session['consent']
    authz_code = request.form['code'] if request.method == 'POST' else request.args.get('code')
    # this calls /auth/token
    #oAuthsession = OAuth2Session(client_id=client_id, client_secret=client_secret, scope=scope)
    #token = oAuthsession.fetch_access_token(OAUTH2_REFTOKEN_URL, code=request.args.get('code'))
    client = get_client(session['oauth2_srvname'])
    token = client.fetch_access_token(session['redirect_uri'], code=authz_code, verify=False) #TODO verify=True for certificate validation
    refresh_token = json.dumps(token['refresh_token'])
    rtoken = OAuth2RefreshToken(user_id=User.query.filter_by(username=session['username']).first().id)
    rtoken.refresh_token = refresh_token
    rtoken.scope = json.dumps(token['scope'])
    rtoken.access_token = json.dumps(token['access_token'])
    rtoken.expires_in = json.dumps(token['expires_in'])
    db.session.add(rtoken)
    db.session.commit()
    return refresh_token
    # return redirect(url_for('scitoken.refreshTokenForm', refresh_token=str(token['refresh_token'])))



@scitoken_bp.route('/scitokens', methods=['POST'])
def generateAccessSciToken():
    token = scitokenins.generateAccessSciToken(request.form.get('parent_token', None), request.form.get('refresh_token', None))
    #return Response('<p>' + str(token.serialize(issuer='local')) + '</p>')
    return token.serialize(issuer='local')
    #return token.serialize(issuer = "local")


@scitoken_bp.route('/resource', methods=['GET'])
def verifyToken(token, action, resource, issuer):
    scitokenins.generateEnforcer()
    return scitokenins.verifyToken(request.args.get('token'), request.args.get('act'),request.args.get('id'))



@scitoken_bp.route('/scitokensval', methods=['POST'])
def validateToken():
    return scitokenins.validate_token(request.form.get('token'))





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



@scitoken_bp.route('/oauth2Form', methods=['GET'])
def codeForm():
    return Response('''
        <form action="'''
           + 'http://127.0.0.1:4006' + url_for('.generateOAuth2') +
        '''" method="post">
            <p><input type=text name=username value="aliveli">
            <p><select name="oauth2_srvname">
                    <option selected="selected">Local</option>
                    <option>Twitter (Not working)</option>
                </select></p>
            <p><input type=text name=redirect_uri value="'''
           + 'http://127.0.0.1:4006' + url_for('.generateOAuth2') +
        '''">
            <p><input type=text name=authz_code value="">
            <p><input type=submit value=submit>
        </form>
    ''')



@scitoken_bp.route('/scitokenForm', methods=['GET'])
def refreshTokenForm():
    return Response('''
        <form action="'''
        + 'http://127.0.0.1:4006' + url_for('.generateAccessSciToken') +
        '''" method="post">
            <p><input type=text name=refresh_token value="">
            <p><input type=submit value=submit>
        </form>
    ''')
