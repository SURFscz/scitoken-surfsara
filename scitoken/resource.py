#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 09/11/2018
#Copyright SurfSara BV

from flask import jsonify
from authlib.flask.oauth2 import ResourceProtector
from authlib.specs.rfc6750 import BearerTokenValidator
from .models import OAuth2Token
from scitoken.models import db


class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return OAuth2Token.query.filter_by(access_token=token_string).first()

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return token.revoked

require_oauth = ResourceProtector()

# only bearer token is supported currently
require_oauth.register_token_validator(MyBearerTokenValidator())

# you can also create BearerTokenValidator with shortcut
from authlib.flask.oauth2.sqla import create_bearer_token_validator

BearerTokenValidator = create_bearer_token_validator(db.session, OAuth2Token)
require_oauth.register_token_validator(BearerTokenValidator())
