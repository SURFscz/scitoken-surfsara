# SciToken Web Library
This demo has been built by using the Python version of the [Scitoken library](https://github.com/scitokens/scitokens). The current version of the library does not have OAuth2 server embedded. In order to run the Scitoken demo, you need an OAuth2 server that can issue `refresh tokens`. 

For the purposes of this demo, we used: 

* [Authlib](https://authlib.org/), an OAuth2 server 
* A fork of the [example OAuth2 server](https://github.com/fturkmen/example-oauth2-server) built by using authlib. The fork merely adds an interface fo verifying the validity of refresh tokens.  

## Requirements
Before running the demo, clone the OAuth2 server fork (feel free to put this to your own Dockerfile): 

```bash
git clone https://github.com/fturkmen/example-oauth2-server.git
```

## Data Model 
Based on the following excerpt from [Refresh Tokens proposal] (https://scitokens.org/scitokens-proposal-public.pdf), the refresh tokens need to be stored locally within the library itself :  
> Users authenticate with identity tokens to submit jobs/workflows, but identity tokens do not travel along with the jobs. Instead, at job submission time the Token Manager obtains OAuth refresh tokens with needed data access privileges from Token Servers. The Token Manager securely stores these relatively long-lived refresh tokens locally, then uses them to obtain short-lived access tokens from the Token Server when needed (e.g., when jobs start or when access tokens for running jobs near expiration). The Scheduler then sends the short-lived access tokens to the jobs, which the jobs use to access remote data.

Based on this, we can infer that there is a refresh token either per user or per job (even though the former is more likely). One could also map a client (or a user) to a single refresh token in different scenarios which is exactly how it is done in Scitoken Web library. 

Client ID | Refresh Token
------------ | -------------
12345 | Job's/User's refresh token

The SciToken library mimics/employs the example OAuth2 server's mixins to generate a storage for the refresh token. The storage configuration is available in **app.py** and the mappings are provided in **models.py**. By default, the refresh tokens are stored in a SQLAlchemy database.  

## API EndPoints
In the demo, there is a simple API to generate, validate, consume and revoke scitokens. The endpoints for the SciToken demo are shown in the `SciTokenAPI.yaml` file.

## Build and Deployment
Deployment of the Oauth2 server is done through container. You first need to build it:

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

# Demo
Here are the steps for running the Scitoken Web library demo.

## Running 
The Scitoken Web library demo is configured with the `app.py` file.

Authentication screen authenticates the user.



# TODOs
1. Instead of `flask runner` employ WSGI 
2. Move to a proper storage (e.g. database)
3. Write unit tests
 
# References and Further Reading
The Scitoken implementation is basedo on Sci
