JWT=$1
curl -k https://isam.local:20443/ssa/ -d $JWT  -H "Content-type: application/jwt" | jq .
