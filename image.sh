BX="au.icr.io"
NAMESPACE="isamob"
VERSION="latest"
SAM_VERSION="latest"

docker tag store/ibmcorp/isam:9.0.7.0_IF1 $BX/$NAMESPACE/isam:$VERSION 
docker tag ibmcom/isam-openldap:$SAM_VERSION $BX/$NAMESPACE/isam-openldap:$VERSION
docker tag ibmcom/isam-postgresql:$SAM_VERSION $BX/$NAMESPACE/isam-postgresql:$VERSION

docker push $BX/$NAMESPACE/isam-openldap:$VERSION 
docker push $BX/$NAMESPACE/isam-postgresql:$VERSION 
docker push $BX/$NAMESPACE/isam:$VERSION 


