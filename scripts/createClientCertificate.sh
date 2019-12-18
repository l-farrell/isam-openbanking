CLIENT_ID=$1

openssl genrsa -out $CLIENT_ID.key 2048
openssl req -new -key $CLIENT_ID.key -out $CLIENT_ID.csr -subj "/C=AU/CN=$CLIENT_ID"
openssl x509 -req -in $CLIENT_ID.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out $CLIENT_ID.crt -days 1825 -sha256 

echo $CLIENT_ID.key created
echo $CLIENT_ID.crt created




