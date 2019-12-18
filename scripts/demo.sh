bold=$(tput bold)
normal=$(tput sgr0)


REDIRECT_URI="https://cdrapp.local:18443"
echo "Fetching Software statement for URI $REDIRECT_URI..."
echo
sleep 1


REDIRECT_URI_ESC=$(echo $REDIRECT_URI | sed 's|/|\\/|g')
SSA=$(bash createSSA.sh "$REDIRECT_URI_ESC" | tail -n 1)

echo "Fetched software statement:"
echo
echo -e "\t${bold}$SSA${normal}"


echo "Discovering OP..."
echo

curl "https://isam.local:20443/isam/sps/oauth/oauth20/metadata/OpenBanking" -S -s -k | jq . 
echo
echo


echo 
echo "Presenting Software statement for registration with the bank..."
echo
sleep 1
SSA_REG=$(bash SSARegister.sh $SSA)
SSA_CLIENT_ID=$(echo $SSA_REG | jq -r .client_id)
echo 
echo "CDR Data reciever registered. Client ID:"
echo -e "\t${bold}$SSA_CLIENT_ID${normal}"


echo "Generating MTLS certificate"

echo


bash createClientCertificate.sh $SSA_CLIENT_ID

echo 
echo
echo -n "Initating Hybrid flow"

sleep 0.2
echo -n .
sleep 0.2
echo -n .
sleep 0.2
echo -n .
echo
echo "Response type: 'code id_token'"
echo "Scope: 'openid profile offline_access'"
echo "Response Mode: 'fragment'"
echo 
URL_TEMPLATE="https://isam.local:20443/isam/sps/oauth/oauth20/authorize?client_id=@CLIENT_ID@&state=someState&nonce=someNonce&scope=openid+profile+offline_access&redirect_uri=https://cdrapp.local:18443&response_type=id_token+code&response_mode=fragment"

URL=$(echo $URL_TEMPLATE | sed "s|@CLIENT_ID@|$SSA_CLIENT_ID|g")


echo "Launching browser with request:"
echo "${bold}$URL${normal}"

echo 

firefox $URL 2>/dev/null &
echo
echo "Waiting for browser flow to complete..."

wait

echo "Browser flow complete. Please enter the authorization code"


read -p "Code:" CODE
echo
echo "Fetching client authentication JWT"

sleep 1
ASSERTION=$(bash createClientAuthJwt.sh "$SSA_CLIENT_ID" | tail -n 1)
echo 
echo "Client Auth Assertion:"
echo
echo -e "\t${bold}$ASSERTION${normal}"
echo

echo "Making MTLS request to /token with client assertion..."

sleep 1
echo

POST_DATA="code=$CODE&grant_type=authorization_code&redirect_uri=$REDIRECT_URI&client_assertion=$ASSERTION&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" 	

BEARER=$(curl -s -S -E ./$SSA_CLIENT_ID.crt --key ./$SSA_CLIENT_ID.key https://isam.local:20443/isam/sps/oauth/oauth20/token -d $POST_DATA -k)
echo
echo "Bearer token:"
echo
echo $BEARER | jq . 
echo

ACR=$(echo $BEARER | jq .id_token  | cut -f 2 -d '.' | sed 's/-/+/g' | sed 's/_/\//g' | base64 -di - | jq -r .acr)
echo -e "ACR of id_token: \n\t${bold}$ACR${normal}"
echo

AT=$(echo $BEARER | jq -r .access_token)
echo "Introspecting bearer token [${bold}$AT${normal}]."
echo
sleep 1
INTROSPECT_DATA="token=$AT&client_assertion=$ASSERTION&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" 	
INTROSPECT=$(curl -s -S https://isam.local:20443/isam/sps/oauth/oauth20/introspect -d $INTROSPECT_DATA -k)

echo "Introspect response:"
echo
echo $INTROSPECT | jq .

MTLS_FINGERPRINT=$(echo $INTROSPECT | jq -r .mtls_fingerprint)

echo -e "MTLS Fingerprint for HoK validation by resource server: \n\t [${bold}$MTLS_FINGERPRINT${normal}]."
echo

ACR=$(echo $INTROSPECT | jq -r .acr)

echo -e "ACR of introspected token: \n\t [${bold}$ACR${normal}]."

