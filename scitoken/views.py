from flask import (
    Blueprint, request, Response, redirect, session
)
import SciTokenClass
import json
from scitoken.oauth2 import get_client

from scitoken.models import OAuth2RefreshToken, db, User

scitokenins = SciTokenClass(1)
scitokenTM = TokenManager()

scitoken_bp = Blueprint('scitoken', __name__)



@scitoken_bp.route('/hello', methods=['GET'])
def index():
    return "<h2>Welcome to SciToken Demo</h2>"


@scitoken_bp.route('/', methods=['GET'])
# This code has been taken from here : https://github.com/authlib/example-oauth2-server
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)


@scitoken_bp.route('/create_oauth2_client', methods=['GET', 'POST'])
def creteOAuth2client():
    return None


@scitoken_bp.route('/oauth2RefreshToken', methods=['GET', 'POST'])
def generateOAuth2():
    '''
    This endpoint follows the Authorization Code flow of OAuth2 to obtain a refresh token.
    Parameters : See the YAML file for more details
    :parameter:  str oauth2ClientName : The client identifier ('local', 'twitter',...)
             for the particular OAuth2 provider
             If POST : OAuth2 service name , user id
             If GET :  redirect_uri, authorization code
    :return: If POST : forwards to consent/login screen
             If GET : obtains the refresh token
    '''
    if request.method == 'GET' : #Consent/authorization screen for the user
        client = get_client(request.form['oauth2ClientName'])
        uri, state = client.generate_authorize_redirect()
        return redirect(uri, code=303)
    else :
        #oAuthsession = OAuth2Session(client_id=client_id, client_secret=client_secret, scope=scope)
        #token = oAuthsession.fetch_access_token(OAUTH2_REFTOKEN_URL, code=request.args.get('code'))
        client = get_client(request.form['oauth2ClientName'])
        token = client.fetch_access_token(request.form['redirect_uri'], code=request.form['code'])
        refresh_token = json.dumps(token['refresh_token'])
        rtoken = OAuth2RefreshToken(session['userid'], refresh_token)
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
