#Created by Fatih Turkmen (fatih.turkmen@surfsara.nl) on 18/10/2018
#Copyright SurfSara BV

# Add additional OAuth2 providers below.

from authlib.flask.client import OAuth

oauth = OAuth()

oauth.register('Local',
    client_id = 'MgNK8cp0VGYsSwtPAHIYusYg',
    client_secret = 'LPPbZE0oiBRSAzl13QDUjZfLbW94JtRtdCZR0gM8NFRUqgub',
    access_token_url = 'https://127.0.0.1:4005/oauth/token',
    authorize_url = 'https://127.0.0.1:4005/oauth/authorize',
    client_kwargs = {'scope': 'read:/home/other/test_file'},
)

# You can add other OAuth2 servers...
# oauth.register('twitter',
#     client_id='Twitter Consumer Key',
#     client_secret='Twitter Consumer Secret',
#     access_token_url='https://api.twitter.com/oauth/access_token',
#     authorize_url='https://api.twitter.com/oauth/authenticate',
#     api_base_url='https://api.twitter.com/1.1/',
#     client_kwargs=None,
# )


def get_client(name='local') :
    return oauth.create_client(name)