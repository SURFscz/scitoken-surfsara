# SciToken Web Library
This demo has been built by using the Python version of the [Scitoken library](https://github.com/scitokens/scitokens). The current version of the library does not have OAuth2 server embedded. In order to run the Scitoken demo, you need an OAuth2 server that can issue `refresh tokens`. 

For the purposes of this work, we used: 

* [Authlib](https://authlib.org/), an OAuth2 server 
* A fork of the [example OAuth2 server](https://github.com/fturkmen/example-oauth2-server) built by using authlib. The fork merely adds an interface fo verifying the validity of refresh tokens.  

## Requirements
Before running the server (that provides a frontend for the library), clone the OAuth2 server fork (feel free to put this to your own Dockerfile): 

```bash
git clone https://github.com/fturkmen/example-oauth2-server.git
```

## Data Model 
Based on the following excerpt from [Refresh Tokens proposal] (https://scitokens.org/scitokens-proposal-public.pdf), the refresh tokens need to be stored locally within the library itself :  
> Users authenticate with identity tokens to submit jobs/workflows, but identity tokens do not travel along with the jobs. Instead, at job submission time the Token Manager obtains OAuth refresh tokens with needed data access privileges from Token Servers. The Token Manager securely stores these relatively long-lived refresh tokens locally, then uses them to obtain short-lived access tokens from the Token Server when needed (e.g., when jobs start or when access tokens for running jobs near expiration). The Scheduler then sends the short-lived access tokens to the jobs, which the jobs use to access remote data.

Based on this, we can infer that there is a refresh token either per user or per job (even though the former is more likely). One could also map a (OAuth2) client to a single refresh token in different scenarios. In the current implementation of the Scitoken Web library, each user has a refresh token. 

User ID | Refresh Token
------------ | -------------
12345 | Job's/User's refresh token

The SciToken library mimics/employs the example OAuth2 server's mixins to generate a storage for the refresh token. The storage configuration is available in **app.py** and the mappings are provided in **models.py**. By default, the refresh tokens are stored in a SQLAlchemy database. The use of `OAuth2TokenMixin` has benefits such as easy integration with OAuth2 server and reuse but also limitations such as unnecessary fields for *refresh tokens* such as scope or access_token. 

 

## API EndPoints
The library allows simple operations to generate, validate and consume scitokens. The endpoints for the SciToken demo are shown in the `SciTokenAPI.yaml` file. 

**IMPORTANT: The endpoint that handles the OAuth2 flow for obtaining refresh tokens is `oauth2RefreshToken`**. So when you provide the `redirect_uri` parameter during OAuth2 registration bear this in mind.

## Build and Deployment

### OAuth2 Server
Deployment of the Oauth2 server is done through a container. You first need to build it:

```bash
docker build -t oauth2server:latest -f Dockerfile_Oauth2Server .
```

And then run it:

```bash
docker run --detach \
           --env X509_CERT_BASE64=your_cert \
           --env X509_CHAIN_BASE64=your_cert_chain \
           --env X509_KEY_BASE64=your_key \
           --name oauth2server \
           -p 4005:4005/tcp \
           oauth2server
```


### Running Scitoken Server
Since the library is a Flask application and the motivation is just to build a running example, the library is run through `flask run`. Obviously there are better ways for scalability and so on (see the ToDo list below). 

For instance, in order to run the server (on `localhost` at `4006`), just run the following at the level of `app.py` :

```bash
flask run --host=127.0.0.1 --port=4006
```



# Demo
There is a simple demo to showcase the use of Scitokens. It is basically a list of HTML pages that show various flow to:

* Obtain a refresh token from the OAuth2 server after giving consent
* Obtain a Scitoken by using the Refresh token and use that for access to a resource (i.e. identified with a resource id)

There are also supporting functionalities such as user management (i.e. registration, login, logout) and token forms for standalone functionality but they are just different pieces put together with a stylesheet from the Internet.



## Running 
The Scitoken Web library demo is configured with the `app.py` file. 

### Notes On Running
Here are several notes that could be important to keep in mind:

* The sessions in flask (not the extensions) are cookie-based which, IMO, makes the development more difficult. That said, it also makes the production/deployment easy along with possible additional benefits. In order to run the scitoken code together with Oauth2 server locally, I needed to set a different `SESSION_COOKIE_NAME` for each application. See `app.py` for both. This is irrelevant if both servers are run on different domains.




# TODOs
- [ ] Implement the `revoke` functionality for the scitokens.
- [ ] Solve the misconfiguration of `logout` method between Scitoken library and OAuth2 server 
- [ ] Implement Validator, Verifier and Enforcer for scitoken. 
- [ ] Example URL resource to be protected by the scitoken.
- [ ] The revocation of refresh tokens and scitokens
- [ ] Certificate validation during refresh token fetch (`verify=True` for certificate validation in ***generateOAuth2()*** method)
- [ ] The OAuth2TokenMixin does not meet refresh token data structure (see the class `OAuth2TokenMixin` in a ***sqla.py***), it has `expires_in` etc. (more suitable for OAuth2 access tokens) -> create a new mixin specific for refresh tokens.
- [ ] Instead of `flask run` employ WSGI 
- [ ] Implement a decorator like `require_auth` of Oauth2 example implementation for Scitokens.
- [ ] A proper storage (e.g. database) from SQLAlchemy local data store
- [ ] Unit tests
- [ ] The issue of fav icon.
- [ ] Employ WTF forms for the demo
- [ ] Give thoughts about making these thread safe
 
 
# Test Cases
- [ ] The mixins, ORMs and so on are working for storing the tokens?
- [ ] The decorated resource is protected?
- [ ] The cases of revoked scitoken and/or refresh tokens work?  
 
# References and Further Reading
The Scitoken implementation is based on Authlib. 
