# SciToken Web Library
This demo has been built by using the Python version of the [Scitoken library](https://github.com/scitokens/scitokens). The current version of the library does not have OAuth2 server embedded. In order to run the Scitoken demo, you need an OAuth2 server that can issue `refresh tokens`. 

For the purposes of this demo, we used [authlib](https://authlib.org/) and a fork of the [example OAuth2 server](https://github.com/fturkmen/example-oauth2-server) built by using authlib.  

## Data Model 
Based on the following excerpt from [Refresh Tokens proposal] (https://scitokens.org/scitokens-proposal-public.pdf), the refresh tokens need to be stored locally within the library itself :  
> At job submission time the Token Manager obtains OAuth refresh tokens with needed data access privileges from Token Servers. The Token Manager securely stores these relatively long-lived refresh tokens locally,
then uses them to obtain short-lived access tokens from the Token Server when needed (e.g., when jobs start or when access tokens for running jobs near expiration). The Scheduler then sends the short-lived access tokens to the jobs, which the jobs use to access remote data.

The SciToken library mimics/employs the example OAuth2 server's mixins to generate a storage for the refresh token.  

## API EndPoints
In the demo, there is a simple API to generate, validate, consume and revoke scitokens. The endpoints for the SciToken demo are shown in the `SciTokenAPI.yaml` file.

## Deployment
Deployment of the demo and the Oauth2 server are done through containers.


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
Authentication screen authenticates the user.

# TODOs
1. Instead of `flask runner` employ WSGI 
2. Write unit tests
3. 

# References and Further Reading
The Scitoken implementation is basedo on Sci
