import scitokens
import subprocess
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# NOTES
# Parent Tokens:
# The tokens can also be chained, i.e. one token can be appended to another.
# By default the new token will default to having all the authorisations of the parent token
# but is mutable and can add further restrictions. Parent tokens are typically generated by a
# separate server and sent as a response to a successful authentication or authorization request
#
# Refresh Tokens:
# The generation of the refresh token will be done according to OAuth2 spec : https://tools.ietf.org/html/rfc6749#section-1.5
# We use authlib of Flask for OAuth2 related functionality.
# The flow here is : An authorization code flow is executed to obtain an authorization code. The authorization code
# then is used to get an access + refresh token...

# Python and Flask Related Readings:
# Post parameter handling : https://scotch.io/bar-talk/processing-incoming-request-data-in-flask
# Tutorial about Flask : https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world



class TokenManager():

    OAUTH2_REFTOKEN_URL = 'https://127.0.0.1:4005/oauth/token'

    # TODO : Check the Scitoken implementation in the coming months to see their RefreshToken feature is implemented
    def generateOAuth2RefreshToken(self, session, authz_code):
        token = session.fetch_access_token(self.OAUTH2_REFTOKEN_URL, code=authz_code)

        # TODO: We need to store the generated Refresh Token
        # The Token Manager securely stores these relatively long-lived refresh tokens locally
        return token['refresh_token']

    # The client send a POST request with:
    # "grant_type" : "refresh_token"
    # "refresh_token" : the original refresh token
    # "client_id" : the ID of the client
    # "client_secret" : client's secret
    # "scope" :  A space-delimited list of requested scope permissions
    # def generateSciRefreshToken(self, refresh_token, client_id, client_secret, scope, authz_code, id_token=None):
    #     session = OAuth2Session(client_id, client_secret, scope=scope)
    #     r_token = scitokens.generate("refresh_token", refresh_token, client_id, client_secret, scope)
    #     access_token_url = 'https://127.0.0.1:4005/oauth/token'
    #     token = session.fetch_access_token(access_token_url, code=authz_code)
    #     return token['refresh_token']


  #TODO: The refresh tokens can also or be invalidated, we need to look at there : https://stackoverflow.com/questions/40555855/does-the-refresh-token-expire-and-if-so-when
    def revokeRefreshToken(self, refToken):
        print("IMPLEMENT THIS...")
        return True






class SciTokenClass():

    VALIDATE_REFTOKEN_URL = 'https://127.0.0.1:4005/oauth/ref_token_validate'

    def generateKeyPairWithRSA(self):
        return generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )


    def __init__(self, keygen_method):
        '''
        :param keygen_method: The key generation method that will be used.
        '''
        if keygen_method == 1:
            self._private_key = self.generateKeyPairWithRSA()
        elif keygen_method == 2: #TODO : Not complete, do not use..
            self._private_key = self.generateKeyPairWithOpenSSL(file)
        validator = scitokens.Validator()
        validator.add_validator("foo", self.always_accept_validator) #Add the token validator method.


    def generateEnforcer(self, issuer="local"):
        return scitokens.Enforcer(issuer)


    # To validate a specific claim, provide a callback function (below) to the Validator object
    def validate_token(self,token):
        '''
        :param token: The scitoken to be validated.
        :return: True or False
        '''
        return self.validator.validate(token)


    # Validator methods...
    def always_accept_validator(self,value):
        '''
        A validator that accepts any value. --> TODO: Taken from the Scitoken repo, needs to be updated...
        '''
        if value or not value:
           return True



    # According to Github, the below should also work but it does not generate a private key
    # and results with MissingKeyException
    # token=scitokens.SciToken()
    # Note: There are different views: refresh tokens never expire or they have an expiry time/date...
    def generateAccessSciToken(self, parent_token = None, refresh_token = None):
        '''
        @param self:
        @param parent_token: The parent token for the new SciToken.
        @param refresh_token: The refresh token that will be used to generate the Scitoken
        @return:
        '''
        payload = {'refresh_token': refresh_token}
        r = requests.post(self.VALIDATE_REFTOKEN_URL, data=payload, verify=False)
        if r.json()['result']:
            token = scitokens.SciToken(key=self._private_key, parent=parent_token)
            serialized_token = token.serialize(issuer = 'local')
            print(serialized_token)
            return token
        else:
            return None


    # The enforcer object is instantiated with the issuer
    # Similarly, the scope of the enforcer can be narrowed down to a specific audience
    # For instance scitokens.Enforcer("https://scitokens.org/dteam", audience="https://example.com")
    # will accept only the tokens for the requests addressed to services of "https://example.com"
    def verifyToken(self, token, action, resource):
        serialized_token = token.serialize(issuer="local")
        token = scitokens.SciToken.deserialize(serialized_token, public_key = self._public_pem, insecure=True)
        # test whether the token holder is allowed to
        self.enf.test(token, action, resource)




    # To validate a specific claim, provide a callback function (below) to the Validator object
    def revoke_token(self,token):
        # TODO : TO BE IMPLEMENTED
        return False  # self.validator.validate(token)

########################################################################

    # https://stackoverflow.com/questions/89228/calling-an-external-command-in-python
    # TBC
    def generateKeyPairWithOpenSSL(self, key_file):
        # call the generate scripts
        p = subprocess.Popen('generate_keys.sh '+key_file, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            print(line)
        #retval = p.wait()


    # To validate a specific claim, provide a callback function (below) to the Validator object
    def validate_NEW_CLAIM(value):
        return value == True


    # This is JWT generation taken from Scitoken Github page which is in return taken from Codacy...
    # TBD...
    def generateJWTToken(self):
        SciTokenClass.generateKeyPair(self, "sample_ecdsa_keypair.pem")
        with open("sample_ecdsa_keypair.pem", "r") as file_pointer:
            serialized_pair = file_pointer.read()

        loaded_public_key = serialization.load_pem_public_key(
            serialized_pair,
            backend=default_backend()
        )
        # Generate a scitoken
        token = scitokens.SciToken()
        return token


