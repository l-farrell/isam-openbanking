#!/bin/bash
REVERSE_PROXY_HOSTNAME=isam.local:20443
USERNAME=testuser
PASSWORD=passw0rd
CLIENT_ID=$1
CLIENT_SECRET=$2
STATE=someState$RANDOM$RANDOM$$
REDIR_URI=https://lmfapp.com:18443

#POST to the login form
curl -b cookieJar.txt -c cookieJar.txt -v -k -d "username=$USERNAME&password=$PASSWORD&login-form-type=pwd" "https://$REVERSE_PROXY_HOSTNAME/pkmslogin.form"
#initial /authorize request
curl -b cookieJar.txt -c cookieJar.txt -vvv -k "https://$REVERSE_PROXY_HOSTNAME/isam/sps/oauth/oauth20/authorize?scope=custom+&response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIR_URI&state=$STATE" -D /tmp/$STATE


cat /tmp/$STATE

# Extract the code
CODE=$(cat /tmp/$STATE| grep -o -P '(?<=code=)[^&]*')

echo code: $CODE

if [[ $CODE ]] ; then
	#Exchange code for an id token at /token, token does not require a cookieJar

	ASSERTION=$3
	POST_DATA="code=$CODE&grant_type=authorization_code&state=$STATE&redirect_uri=$REDIR_URI&client_id=$CLIENT_ID&client_assertion=$ASSERTION&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" 	

	curl -k -u $CLIENT_ID:$CLIENT_SECRET https://$REVERSE_PROXY_HOSTNAME/isam/sps/oauth/oauth20/token -d $POST_DATA
fi 

#Make it stateless
rm cookieJar.txt
