JWT=$1
curl -s -S -k https://isam.local:20443/ssa/ -d $JWT  -H "Content-type: application/jwt" 
