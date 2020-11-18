import requests
import json
from pprint import pprint as pp
from .config import *

databricks_base_url = f'https://{databricks_deployment}.cloud.databricks.com'
databricks_saml_url = f'{databricks_base_url}/saml/consume'


def parse_result(action: str, result):
    try:
        if not result.ok:
            raise Exception(f'{action}: {result.text} {result.status_code}')
    except Exception as ex:
        pp(ex)


# Request a token
token = json.loads(requests.post(
    f'{keycloak_base_url}/auth/realms/master/protocol/openid-connect/token',
    data={
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': keycloak_username,
        'password': keycloak_password
    }
).text)['access_token']

# Create realm
api_result = requests.post(
    f'{keycloak_base_url}/auth/admin/realms',
    data=json.dumps({
        'realm': keycloak_realm,
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
    f'{keycloak_base_url}/auth/admin/realms/{keycloak_realm}/clients/{keycloak_client_id}',
    headers={
        'Authorization': f'bearer {token}'
    }
)
parse_result('Delete client', api_result)

# Create client
api_result = requests.post(
    f'{keycloak_base_url}/auth/admin/realms/{keycloak_realm}/clients',
    data=json.dumps({
        'id': keycloak_client_id,
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
    f'{keycloak_base_url}/auth/realms/{keycloak_realm}/protocol/openid-connect/certs',
    headers={
        'Authorization': f'bearer {token}'
    }
).json()

# Print values to use when setting up Databricks SSO
print(f'Databricks SAML URL: {databricks_saml_url}')
print(f'Single Sign-On URL: {keycloak_base_url}/auth/realms/{keycloak_realm}/protocol/saml')
print(f'Identity Provider Entity ID: {keycloak_client_id}')
print(f'x.509 Certificate: {certs["keys"][0]["x5c"][0]}')
