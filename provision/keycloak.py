import requests
import json
from pprint import pprint as pp
from dynaconf import Dynaconf


class KeycloakAPI:
    def __init__(self, settings: Dynaconf):
        self.settings = settings
        self.databricks_base_url = f'https://{self.settings.databricks_deployment}.cloud.databricks.com'
        self.databricks_saml_url = f'{self.databricks_base_url}/saml/consume'
        self.keycloak_realm = settings.keycloak_realm
        self.keycloak_base_url = settings.keycloak_base_url
        self.keycloak_client_id = settings.keycloak_client_id

        # Request a token
        token = json.loads(requests.post(
            f'{self.keycloak_base_url}/auth/realms/master/protocol/openid-connect/token',
            data={
                'grant_type': 'password',
                'client_id': 'admin-cli',
                'username': settings.keycloak_username,
                'password': settings.keycloak_password
            }
        ).text)['access_token']

        self.authorization_header = {'Authorization': f'bearer {token}'}
        self.content_type_header = {'content-type': 'application/json'}

    def create_realm(self):
        KeycloakAPI.parse_result(
            'Create realm',
            requests.post(
                f'{self.keycloak_base_url}/auth/admin/realms',
                data=json.dumps({
                    'realm': self.keycloak_realm,
                    'enabled': True
                }),
                headers={**self.authorization_header, **self.content_type_header}
            )
        )

    def get_realms(self):
        return requests.get(
            f'{self.keycloak_base_url}/auth/admin/realms',
            headers={**self.authorization_header, **self.content_type_header}
        ).json()

    def get_realm(self):
        return [realm for realm in self.get_realms() if self.keycloak_realm == realm['realm']]

    def delete_realm(self):
        if 1 == len(self.get_realm()):
            KeycloakAPI.parse_result(
                'Delete realm',
                requests.delete(
                    f'{self.keycloak_base_url}/auth/admin/realms/{self.keycloak_realm}',
                    headers=self.authorization_header
                )
            )

    def create_client(self):
        KeycloakAPI.parse_result(
            'Create client',
            requests.post(
                f'{self.keycloak_base_url}/auth/admin/realms/{self.keycloak_realm}/clients',
                data=json.dumps({
                    'id': self.keycloak_client_id,
                    'baseUrl': self.databricks_base_url,
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
                        f'{self.databricks_saml_url}'
                    ],
                    'adminUrl': f'{self.databricks_saml_url}'
                }),
                headers={**self.authorization_header, **self.content_type_header}
            )
        )

    def get_clients(self):
        clients = requests.get(
            f'{self.keycloak_base_url}/auth/admin/realms/{self.keycloak_realm}/clients',
            headers={**self.authorization_header, **self.content_type_header}
        ).json()
        return clients if 'error' not in clients else []

    def get_client(self) -> list:
        clients = [client for client in self.get_clients() if self.keycloak_client_id == client['clientId']]
        return clients[0] if 1 == len(clients) else None

    def delete_client(self):
        if self.get_client() is not None:
            KeycloakAPI.parse_result(
                'Delete client',
                requests.delete(
                    f'{self.keycloak_base_url}/auth/admin/realms/{self.keycloak_realm}/clients/{self.keycloak_client_id}',
                    headers=self.authorization_header
                )
            )

    def get_certificates(self):
        return requests.get(
            f'{self.keycloak_base_url}/auth/realms/{self.keycloak_realm}/protocol/openid-connect/certs',
            headers=self.authorization_header
        ).json()

    def get_certificate(self):
        certificates = self.get_certificates()
        if 'keys' in certificates:
            return certificates["keys"][0]["x5c"][0]
        return None

    @staticmethod
    def parse_result(action: str, result):
        try:
            if not result.ok:
                raise Exception(f'{action}: {result.text} {result.status_code}')
            print(f'{action}: {result.status_code}')
        except Exception as ex:
            pp(ex)


if '__main__' == __name__:
    keycloak_api = KeycloakAPI(Dynaconf(
        environments=True,
        settings_file='keycloak.yaml'
    ))

    keycloak_api.delete_client()
    keycloak_api.delete_realm()

    keycloak_api.create_realm()
    keycloak_api.create_client()

    certificate = keycloak_api.get_certificate()

    if certificate is not None and keycloak_api.get_client() is not None:
        print(f'Databricks SAML URL: {keycloak_api.databricks_saml_url}')
        print(
            f'Single Sign-On URL: {keycloak_api.keycloak_base_url}/auth/realms/{keycloak_api.keycloak_realm}/protocol/saml'
        )
        print(f'Identity Provider Entity ID: {keycloak_api.keycloak_client_id}')
        print(f'x.509 Certificate: {certificate}')
    else:
        print(f'Realm [{keycloak_api.keycloak_realm}] or client [{keycloak_api.keycloak_client_id}] not created')