"""
Keycloak bootstrap helpers.

Mostly meant to ease testing.

ENV Variables:
    * KEYCLOAK_URL: base url to keycloak server
    * KEYCLOAK_ADMIN_USERNAME: admin username
    * KEYCLOAK_ADMIN_PASSWORD: admin password
    * KEYCLOAK_REALM: keycloak realm where users are defined
    * KEYCLOAK_CLIENT_ID: admin keycloak client id
"""

import argparse
import logging

from cachetools import TTLCache
import krs.bootstrap
import requests
from wipac_dev_tools import from_environment


class Bootstrap:
    def __init__(self, keycloak_url: str | None = None, keycloak_admin_username: str | None = None, keycloak_admin_password: str | None = None, keycloak_realm: str | None = None):
        self._cfg = from_environment({
            'KEYCLOAK_URL': keycloak_url,
            'KEYCLOAK_ADMIN_USERNAME': keycloak_admin_username,
            'KEYCLOAK_ADMIN_PASSWORD': keycloak_admin_password,
            'KEYCLOAK_REALM': keycloak_realm,
        })

        # figure out keycloak base url
        self.keycloak_url = krs.bootstrap.keycloak_base_url(url=self._cfg['KEYCLOAK_URL'])  # pyright: ignore[reportArgumentType]

        # cache the token for short periods (enough for setup)
        self._token_cache = TTLCache(maxsize=1, ttl=60)

    @property
    def keycloak_admin_token(self):
        if 'keycloak_admin_token' not in self._token_cache:
            self._token_cache['keycloak_admin_token'] = krs.bootstrap.get_token(
                base_url=self.keycloak_url,
                username=self._cfg['KEYCLOAK_ADMIN_USERNAME'],  # pyright: ignore[reportArgumentType]
                password=self._cfg['KEYCLOAK_ADMIN_PASSWORD'],  # pyright: ignore[reportArgumentType]
            )
        return self._token_cache['keycloak_admin_token']

    def bootstrap_realm(self):
        krs.bootstrap.create_realm(
            realm=self._cfg['KEYCLOAK_REALM'],  # pyright: ignore[reportArgumentType]
            token=self.keycloak_admin_token,
            base_url=self.keycloak_url,
        )

    def delete_realm(self):
        krs.bootstrap.delete_realm(
            realm=self._cfg['KEYCLOAK_REALM'],  # pyright: ignore[reportArgumentType]
            token=self.keycloak_admin_token,
            base_url=self.keycloak_url,
        )

    def bootstrap_client(self, client_id, root_url: str | None = None) -> str:
        """
        Bootstrap an oauth2 client.
        
        Returns:
            str: client secret
        """
        base_url = self.keycloak_url
        token = self.keycloak_admin_token
        realm = self._cfg['KEYCLOAK_REALM']  # pyright: ignore[reportArgumentType]
        url = f'{base_url}/admin/realms/{realm}/clients'
        r = requests.get(url, headers={'Authorization': f'bearer {token}'})
        r.raise_for_status()
        clients = r.json()

        if not any(c['clientId'] == client_id for c in clients):
            logging.info(f'creating client "{client_id}"')
            url = f'{base_url}/admin/realms/{realm}/clients'
            args = {
                'authorizationServicesEnabled': False,
                'clientId': client_id,
                'consentRequired': False,
                'defaultClientScopes': ['web-origins', 'roles', 'profile'],
                'directAccessGrantsEnabled': True,
                'enabled': True,
                'fullScopeAllowed': True,
                'implicitFlowEnabled': False,
                'optionalClientScopes': ['offline_access', 'microprofile-jwt', 'email'],
                'serviceAccountsEnabled': False,
                'standardFlowEnabled': True,
                'publicClient': False,
            }
            if root_url:
                args['rootUrl'] = root_url
                args['redirectUris'] = [f'{root_url}/*']
            r = requests.post(url, json=args, headers={'Authorization': f'bearer {token}'})
            try:
                r.raise_for_status()
            except Exception:
                logging.info(r.text)
                raise

            url = f'{base_url}/admin/realms/{realm}/clients'
            r = requests.get(url, headers={'Authorization': f'bearer {token}'})
            r.raise_for_status()
            clients = r.json()
            if not any(c['clientId'] == client_id for c in clients):
                raise Exception(f'failed to create client {client_id}')
            logging.info(f'created client "{client_id}"')
        else:
            logging.info(f'client "{client_id}" already exists')

        kc_id = None
        for c in clients:
            if c['clientId'] == client_id:
                kc_id = c['id']
                break

        # get service account secret
        url = f'{base_url}/admin/realms/{realm}/clients/{kc_id}/client-secret'
        r = requests.get(url, headers={'Authorization': f'bearer {token}'})
        r.raise_for_status()
        if 'value' not in r.json():
            url = f'{base_url}/admin/realms/{realm}/clients/{kc_id}/client-secret'
            r = requests.post(url, headers={'Authorization': f'bearer {token}'})
            r.raise_for_status()
        return r.json()['value']


def main():
    args = argparse.ArgumentParser('Bootstrap Keycloak')
    args.add_argument('--keycloak-url', default='http://localhost:8080', help='Keycloak base url')
    args.add_argument('--keycloak-admin-username', default='admin', help='Keycloak admin username')
    args.add_argument('--keycloak-admin-password', default='admin', help='Keycloak admin password')
    args.add_argument('--keycloak-realm', default='testrealm', help='Keycloak realm to use')
    args.add_argument('--client-id', default='testclient', help='Client Id')
    args.add_argument('--client-url', default=None, help='Client root url (for redirects)')
    arg_dict = vars(args.parse_args())

    client_id = arg_dict.pop('client_id')
    client_url = arg_dict.pop('client_url')
    b = Bootstrap(**arg_dict)
    b.bootstrap_client(client_id=client_id, root_url=client_url)


if __name__ == '__main__':
    main()
