#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 07/06/2018

from flask import Flask,render_template
import os
from scitoken.views import scitoken_bp
from scitoken.models import db

def page_not_found(e):
  return render_template('404.html'), 404


def create_app(config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.register_error_handler(404, page_not_found)

    # load the test config if passed in
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)

    # ensure the instance folder exists, the perfect place to drop things that either change at
    # runtime or configuration files
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # TODO : Investigate the use of clients...
    #oauth = OAuth()
    #oauth.init_app(app)
    #scitokenOAuthSrv = oauth.register('scitokenOAuthSrv',
    #                         client_id='lQ0IRkX4UvcmfKftr2A6F2ay',
    #                         client_secret='QW7tVHlTAHTVkBijrDsrNnEIWRXpCpDP2m5pF3baU0HWFVGG',
    #                         access_token_url='https://127.0.0.1:4005/oauth/token',
    #                         authorize_url='https://127.0.0.1/oauth/authorize'
    #                         )

    setup_app(app)
    return app


def setup_app(app):
    db.init_app(app)
    app.register_blueprint(scitoken_bp)