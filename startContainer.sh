#!/usr/bin/env bash

# Prepare some configuration
if [ ! -d /certs ]; then
    mkdir /certs
fi

chmod 755 /certs
echo "${X509_CERT_BASE64}" | base64 -d > /certs/sp-cert.crt
#echo "${X509_CHAIN_BASE64}" | base64 -d > /certs/ca-chain.pem
echo "${X509_KEY_BASE64}" | base64 -d > /certs/sp-private-key.pem

chmod 644 /certs/*
chmod 600 /certs/sp-private-key.pem

# And pass execution to the 'normal' command

flask initdb

exec flask run --host=0.0.0.0 --port=4005 --cert=/certs/sp-cert.crt --key=/certs/sp-private-key.pem 

