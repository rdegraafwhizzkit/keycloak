import requests
import json
from pprint import pprint as pp
from dynaconf import Dynaconf

s = Dynaconf(
    environments=True,
    settings_file='keycloak.yaml'
)

databricks_base_url = f'https://{s.databricks_deployment}.cloud.databricks.com'
databricks_saml_url = f'{databricks_base_url}/saml/consume'


def parse_result(action: str, result):
    try:
        if not result.ok:
            raise Exception(f'{action}: {result.text} {result.status_code}')
    except Exception as ex:
        pp(ex)


# Request a token
token = json.loads(requests.post(
    f'{s.keycloak_base_url}/auth/realms/master/protocol/openid-connect/token',
    data={
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': s.keycloak_username,
        'password': s.keycloak_password
    }
).text)['access_token']

# Create realm
api_result = requests.post(
    f'{s.keycloak_base_url}/auth/admin/realms',
    data=json.dumps({
        'realm': s.keycloak_realm,
        'enabled': True
    }),
    headers={
        'content-type': 'application/json',
        'Authorization': f'bearer {token}'
    }
)
parse_result('Create realm', api_result)

# Delete existing client if present
api_result = requests.delete(
    f'{s.keycloak_base_url}/auth/admin/realms/{s.keycloak_realm}/clients/{s.keycloak_client_id}',
    headers={
        'Authorization': f'bearer {token}'
    }
)
parse_result('Delete client', api_result)

# Create client
api_result = requests.post(
    f'{s.keycloak_base_url}/auth/admin/realms/{s.keycloak_realm}/clients',
    data=json.dumps({
        'id': s.keycloak_client_id,
        'baseUrl': databricks_base_url,
        'protocol': 'saml',
        'fullScopeAllowed': False,
        'attributes': {
            'saml.assertion.signature': True,
            'saml_force_name_id_format': True,
            'saml_name_id_format': 'email',
            'saml.server.signature': False,
            'saml.client.signature': False
        },
        'redirectUris': [
            f'{databricks_saml_url}'
        ],
        'adminUrl': f'{databricks_saml_url}'
    }),
    headers={
        'content-type': 'application/json',
        'Authorization': f'bearer {token}'
    }
)
parse_result('Create client', api_result)

certs = requests.get(
    f'{s.keycloak_base_url}/auth/realms/{s.keycloak_realm}/protocol/openid-connect/certs',
    headers={
        'Authorization': f'bearer {token}'
    }
).json()

# Print values to use when setting up Databricks SSO
print(f'Databricks SAML URL: {databricks_saml_url}')
print(f'Single Sign-On URL: {s.keycloak_base_url}/auth/realms/{s.keycloak_realm}/protocol/saml')
print(f'Identity Provider Entity ID: {s.keycloak_client_id}')
print(f'x.509 Certificate: {certs["keys"][0]["x5c"][0]}')
