#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 07/06/2018
import time

from flask_bcrypt import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from authlib.flask.oauth2.sqla import OAuth2TokenMixin, OAuth2ClientMixin


# NOTE : This class is very similar to the one of Authlib...

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'

    username = db.Column(db.String(40), primary_key=True)
    password_hash = db.Column(db.String(40))  # TODO : This will be the hash of the password...
    authenticated = db.Column(db.Boolean, default=False)

    def __str__(self):
        return self.username


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.username

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False
    


class OAuth2RefreshToken(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_refreshtoken'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.username', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_expired(self):
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at < time.time()


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
         db.Integer, db.ForeignKey('user.username', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.username', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_expired(self):
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at < time.time()