#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 28/09/2018
#Copyright SurfSara BV

from scitoken import create_app


app = create_app({
    'SECRET_KEY': 'my_application_secret_key',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})



@app.cli.command()
def initdb():
    from scitoken.models import db
    db.create_all()