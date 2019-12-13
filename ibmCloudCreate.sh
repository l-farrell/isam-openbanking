kubectl apply -f secrets.yaml
kubectl create secret generic postgresql-keys --from-file db.key
kubectl create secret generic openldap-keys

kubectl create -f ibmcloudTemplates.yaml 
