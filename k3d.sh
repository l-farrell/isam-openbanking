#k3d create --publish 20443:30443@k3d-k3s-default-worker-0 --publish 20442:30442@k3d-k3s-default-worker-0 --publish 20444:30444@k3d-k3s-default-worker-0 --workers 2  --volume /home/lmf/.k3d/registries.yaml:/etc/rancher/k3s/registries.yaml

kubectl apply -f secrets.yaml
kubectl create secret generic postgresql-keys --from-file db.key
kubectl create secret generic openldap-keys

kubectl create -f k3dtemplates.yaml 

