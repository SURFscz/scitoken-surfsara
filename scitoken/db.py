from authlib.specs.rfc6749 import (TokenMixin)
from sqlalchemy import Column, String, Boolean


class OAuth2TokenMixin(TokenMixin):
    __tablename__ = 'oauth2_refresh_tokens'


    client_id = Column(String(48),primary_key=True)
    refresh_token = Column(String(255), index=True)
    revoked = Column(Boolean, default=False)

    def get_refresh_token(self):
        return self.refresh_token