#!/bin/bash

#Generate a self-signed ssl cert, and put it into a secret named "ssl-private" and "ssl-public"


kubectl delete secret ssl 
openssl genrsa -out db.key 2048
openssl req -new -x509 -key db.key -out db.pem -days 365 -subj '/C=AU/CN=isam'

