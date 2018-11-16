#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 28/09/2018
#Copyright SurfSara BV

from scitoken import create_app
import os

app = create_app({
    'SECRET_KEY': 'secret',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
    'SESSION_COOKIE_NAME': 'scitoken'
})



@app.cli.command()
def initdb():
    from scitoken.models import db
    db.create_all()
