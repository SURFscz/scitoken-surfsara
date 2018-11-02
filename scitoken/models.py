#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 07/06/2018
import time
from flask_sqlalchemy import SQLAlchemy
from authlib.flask.oauth2.sqla import OAuth2TokenMixin, OAuth2ClientMixin


db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password == 'valid'


class OAuth2RefreshToken(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_refreshtoken'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_expired(self):
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at < time.time()


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
         db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')