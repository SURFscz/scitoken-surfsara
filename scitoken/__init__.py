#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 07/06/2018

from flask import Flask,render_template
import os
from scitoken.viewsSciToken import scitoken_bp, scitoken_bp_tm
from scitoken.models import db
from scitoken.oauth2 import oauth

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

    setup_app(app)
    return app


def setup_app(app):
    db.init_app(app)
    oauth.init_app(app)
    app.register_blueprint(scitoken_bp)
    app.register_blueprint(scitoken_bp_tm)