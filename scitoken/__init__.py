#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 07/06/2018

from flask import Flask,render_template
import os
from authlib.flask.client import OAuth



def page_not_found(e):
  return render_template('404.html'), 404


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.register_error_handler(404, page_not_found)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass


    from scitoken.views import scitoken_bp
    app.register_blueprint(scitoken_bp)
    # TODO : Investigate the use of clients...
    #oauth = OAuth()
    #oauth.init_app(app)
    #scitokenOAuthSrv = oauth.register('scitokenOAuthSrv',
    #                         client_id='lQ0IRkX4UvcmfKftr2A6F2ay',
    #                         client_secret='QW7tVHlTAHTVkBijrDsrNnEIWRXpCpDP2m5pF3baU0HWFVGG',
    #                         access_token_url='https://127.0.0.1:4005/oauth/token',
    #                         authorize_url='https://127.0.0.1/oauth/authorize'
    #                         )

    return app