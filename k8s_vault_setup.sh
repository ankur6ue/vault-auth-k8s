#!/bin/bash

# Input param specifies the IP address of the EC2 instance running Vault
if [ -z "$1" ]
  then
    echo "Must provide Vault IP address"
    exit
fi

VAULT_SERVER_USER_NAME="ec2-user"
VAULT_SERVER_IP="$1"
SSH_KEY_LOCATION=~/.ssh/id_rsa
SA_NAME=vault-auth
# Pre-reqs:
# Create a service account for vault kubernetes auth:
# kubectl create sa vault-auth
# Create a ClusterRoleBinding to grant the vault-auth service account access to the TokenReview API
# kubectl apply -f vault-auth-sa.yaml

# Get secret name corresponding to the vault service account
VAULT_SA_NAME=$(kubectl get sa $SA_NAME --output jsonpath="{.secrets[*]['name']}")
SA_JWT_TOKEN=$(kubectl get secret $VAULT_SA_NAME --output 'go-template={{ .data.token }}' | base64 --decode)

#####################################################
export SA_CA_CRT=$(kubectl config view --raw --minify --flatten \
    --output 'jsonpath={.clusters[].cluster.certificate-authority-data}' | base64 --decode)
echo "writing Kubernetes CA CRT to ca_crt.txt"
tee ca_crt.txt<<<$SA_CA_CRT
# This awk command subfunction removes each line break (\r),
# and prints output without new line, adding \n text after each line read, ultimately generating a single line output.
# This can optionally be redirected to a file as desired.
SA_CA_CRT_=`awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' ca_crt.txt`

echo "writing Kubernetes CA CRT to ca_crt.txt"
tee ca_crt.txt<<<$SA_CA_CRT_
#####################################################
# Get the host address of the kubernetes cluster
export K8S_HOST=$(kubectl config view --raw --minify --flatten \
    --output 'jsonpath={.clusters[].cluster.server}')

# Write the config on vault server. Can also use a temp token to send this info in a HTTP post request
# The service account issuer may be different for your cluster. See "Discovering the service account issuer"
# section here: https://www.vaultproject.io/docs/auth/kubernetes#configuring-kubernetes
ssh -tt $VAULT_SERVER_USER_NAME@$VAULT_SERVER_IP -i $SSH_KEY_LOCATION << EOF
export VAULT_ADDR=http://0.0.0.0:8200;
vault auth enable kubernetes;
vault write auth/kubernetes/config  token_reviewer_jwt="$SA_JWT_TOKEN" kubernetes_host="$K8S_HOST" \
 kubernetes_ca_cert="$SA_CA_CRT_" issuer="https://api.internal.dev.k8s.local";
 exit
EOF



