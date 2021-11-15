import json
import os
import requests
from requests import ConnectionError, HTTPError


def read_policy(vault_server_addr: str, policy_name: str, token: str):
    url = vault_server_addr + '/v1/sys/policy/' + policy_name
    try:
        resp = requests.request('GET', url, headers={"X-Vault-Token": token}, timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


def create_policy(vault_server_addr: str, secret_path: str, policy_name: str, token: str):
    url = vault_server_addr + '/v1/sys/policy/' + policy_name
    policy_str = 'path "kv/{0}/*" {{capabilities = ["create", "read", "update", "delete", "list"]}}'.format(secret_path)
    try:
        resp = requests.request('POST', url, headers={"X-Vault-Token": token}, data= \
            {"policy": policy_str},
                                timeout=2)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


# Note: To delete this role on the vault server, use:  vault delete auth/kubernetes/role/dev_role_k8s
def read_role(vault_server_addr: str, vault_role: str, token: str):
    url = vault_server_addr + '/v1/auth/kubernetes/role/' + vault_role
    try:
        resp = requests.request('GET', url, headers={"X-Vault-Token": token}, timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError as e:
        print('We failed to reach a server.')
        return
    return resp


def create_role(vault_server_addr: str, vault_role: str, token: str, vault_policy: str, k8s_svc_acc: str):
    url = vault_server_addr + '/v1/auth/kubernetes/role/' + vault_role
    try:
        resp = requests.request('POST', url, headers={"X-Vault-Token": token}, data= \
            {
                "bound_service_account_names": k8s_svc_acc,
                "bound_service_account_namespaces": "default",
                "policies": vault_policy,
                "ttl": 1
            }
           )
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


def write_vault_secret(vault_server_addr: str, client_token: str, secret_path: str, secret: str):
    url = vault_server_addr + '/v1/kv/' + secret_path + '/config'
    try:
        # Authorization HTTP Header using the Bearer <token> scheme.
        resp = requests.request('POST', url, headers={"X-Vault-Token": client_token}, data=json.dumps(secret),
                                timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


def get_vault_secret(vault_server_addr: str, client_token: str, secret_path: str):
    # First get client authorization token

    url = vault_server_addr + '/v1/kv/' + secret_path + '/config'
    try:
        resp = requests.request('GET', url, headers={"X-Vault-Token": client_token}, timeout=1)
        # Can also use this:
        # resp = requests.request('GET', url, headers={"Authorization": "Bearer " + client_token}, timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    if resp.ok:
        return resp.json()


def get_client_token(vault_server_addr: str, vault_role: str, k8s_jwt_token: str):
    url = vault_server_addr + '/v1/auth/kubernetes/login'
    try:
        resp = requests.request('POST', url, data={"jwt": k8s_jwt_token, "role": vault_role})
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError as e:
        print('We failed to reach a server.')
        print('Reason: ', e.reason)
        return

    return resp

def run():
    # Public IP address of the EC2 instance where vault is running
    vault_server_addr = os.getenv('VAULT_ADDR')
    # name of the vault policy that enables CRUD operations on SECRET_PATH
    vault_policy = os.getenv('VAULT_POLICY')
    # name of the vault role that will be associated with the AWS IAM Role and vault_policy
    vault_role = os.getenv('VAULT_ROLE')
    vault_root_token = os.getenv('VAULT_ROOT_TOKEN')
    k8s_sa_name = os.getenv('K8S_SA_NAME')
    # The path where secret will be written/read
    secret_path = os.getenv('SECRET_PATH')
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
        k8s_jwt_token = f.read()

    # Check to see if the vault policy required to perform operations at path kv/aws-auth-test/* already exists
    resp = read_policy(vault_server_addr, vault_policy, vault_root_token)
    # If not, let's create a policy
    if resp is None or resp.ok == False:
        resp = create_policy(vault_server_addr, secret_path, vault_policy, vault_root_token)
        if resp and resp.ok:
            print("vault policy created successfully")

    if resp and resp.ok:
        # Try creating the role if it doesn't already exist
        # must first call vault auth enable aws on vault server
        # First check if role exists
        resp = read_role(vault_server_addr, vault_role, vault_root_token)
        if resp is None or resp.ok == False:
            # role doesn't exist, let's try to create it. We'll bind this role with the AWS IAM Role that will
            # serve as our identity and attach the policy created above to the role.
            resp = create_role(vault_server_addr, vault_role, vault_root_token, vault_policy, k8s_sa_name)
            print("vault role created successfully")

    if resp is None or resp.ok == False:
        print("unable to read/create vault policy/role, exiting")
        exit(0)

    # Use the service account token to authenticate with vault
    resp = get_client_token(vault_server_addr, vault_role, k8s_jwt_token)

    if resp and resp.ok:
        print("successful login to vault using kubernetes SA authorization")
        client_token = resp.json()['auth']['client_token']
    else:
        print('Failed to login using kubernetes SA authorization, exiting')
        exit(0)
    # write secret
    secret = {
        "data": {
            "foo": "bar",
            "zip": "zap"
        }
    }
    # Use the token to write a secret
    resp = write_vault_secret(vault_server_addr, client_token, secret_path, secret)
    if resp.ok:
        # read secret back
        resp = get_vault_secret(vault_server_addr, client_token, secret_path)
        if resp:
            # compare retrieved secret with master copy
            retrieved_secret = resp["data"]
            if retrieved_secret == secret:
                print("retrieved secret: {0}".format(retrieved_secret))
                print("retrieved secret matches master copy")


if __name__ == '__main__':
    run()


