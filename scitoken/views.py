from flask import (
    Blueprint, request, Response, redirect, url_for, session
)
import SciTokenClass
import json
from authlib.client import OAuth2Session


scitokenins = SciTokenClass.SciTokenClass(1)
scitokenTM = SciTokenClass.TokenManager()

scitoken_bp = Blueprint('scitoken', __name__)


OAUTH2_CONSENT_URL = 'https://127.0.0.1:4005/oauth/authorize'
OAUTH2_REFTOKEN_URL = 'https://127.0.0.1:4005/oauth/token'

client_id='ajWMmlg5AJmmBYUvsaiAov4i'
client_secret='pnPuBacJPRNZ2CVDmorORqwPwTp17a8HZXfMsRdI88J9dckS'
scope = 'profile'


@scitoken_bp.route('/', methods=['GET'])
@scitoken_bp.route('/hello', methods=['GET'])
def index():
    return "<h2>Welcome to SciToken Demo</h2>"



@scitoken_bp.route('/oauth2RefreshToken', methods=['GET', 'POST'])
def generateOAuth2():
    # TODO: The below call needs to be modified when the Scitoken code supports refresh tokens...
    # TODO: For the time being I employ OAuth2..
    if request.method == 'POST' :
        oAuthsession = OAuth2Session(client_id=client_id, client_secret=client_secret, scope=scope)
        uri, state = oAuthsession.authorization_url(OAUTH2_CONSENT_URL) #,redirect_uri=url_for('scitoken.generateOAuth2')
        return redirect(uri, code=303)
    else :
        oAuthsession = OAuth2Session(client_id=client_id, client_secret=client_secret, scope=scope)
        token = oAuthsession.fetch_access_token(OAUTH2_REFTOKEN_URL, code=request.args.get('code'))
        return json.dumps(token['refresh_token'])
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



@scitoken_bp.route('/oauth2Form', methods=['GET'])
def codeForm():
    return Response('''
        <form action="http://127.0.0.1:4006/oauth2RefreshToken" method="post">
            <p><input type=text name=client_id value="ajWMmlg5AJmmBYUvsaiAov4i">
            <p><input type=text name=client_secret value="pnPuBacJPRNZ2CVDmorORqwPwTp17a8HZXfMsRdI88J9dckS">
            <p><input type=text name=scope value="profile">
            <p><input type=submit value=submit>
        </form>
    ''')

@scitoken_bp.route('/scitokenForm', methods=['GET'])
def refreshTokenForm():
    return Response('''
        <form action="http://127.0.0.1:4006/scitokens" method="post">
            <p><input type=text name=refresh_token value="'''+ request.json['refresh_token'] + '''">
            <p><input type=submit value=submit>
        </form>
    ''')
