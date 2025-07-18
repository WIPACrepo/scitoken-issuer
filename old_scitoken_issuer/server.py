# type: ignore
"""
Server for scitoken issuer
"""

import base64
import logging

from tornado.web import HTTPError, authenticated
from rest_tools.server import RestServer, RestHandler, RestHandlerSetup, OpenIDLoginHandler
from rest_tools.utils import from_environment



class Main(RestHandler):
    def initialize(self, issuer, **kwargs):
        super().initialize(**kwargs)
        self.issuer = issuer

    async def get(self, *args):
        auth = self.request.headers.get('Authorization', '')
        method = self.request.headers.get('X-Original-Method', '')
        path = self.request.headers.get('X-Original-URI', '')

        parts = auth.split(' ', 1)
        if parts[0].lower() != 'bearer' or not len(parts) == 2:
            raise HTTPError(403, reason='must supply a bearer token')
        raw_token = parts[1]

        if token := self.validator(raw_token, method, path):
            if 'sub' not in token:
                raise HTTPError(403, reason='sub not in token')
            logging.info(f'valid request for user {token["sub"]}: {method}:{path}')
            self.set_header('REMOTE_USER', token['sub'])
            if uid := token.get('posix', {}).get('uid', None):
                self.set_header('X_UID', uid)
            if gid := token.get('posix', {}).get('gid', None):
                self.set_header('X_UID', gid)
            self.write('')
        else:
            self.send_error(403, 'not authorized')


class TestHandler(RestHandler):
    def initialize(self, issuer, **kwargs):
        super().initialize(**kwargs)
        self.issuer = issuer

    @authenticated
    async def get(self, *args):
        self.write(self.get_secure_cookie('refresh_token'))


def create_server():
    default_config = {
        'HOST': 'localhost',
        'PORT': 8080,
        'BASE_URL': '/',
        'DEBUG': False,
        'COOKIE_SECRET': base64.b16encode(b'secret'),
        'KEYCLOAK_URL': None,
        'KEYCLOAK_REALM': 'IceCube',
        'KEYCLOAK_CLIENT_ID': None,
        'KEYCLOAK_CLIENT_SECRET': None,
        'ISSUER': None,
        'AUDIENCE': None,
    }
    config = from_environment(default_config)

    rest_config = {
        'debug': config['DEBUG'],
        'auth': {
            'openid_url': f'{config["KEYCLOAK_URL"]}/auth/realms/{config["KEYCLOAK_REALM"]}'
        }
    }
    kwargs = RestHandlerSetup(rest_config)
    login_kwargs = kwargs.copy()
    login_kwargs.update({
        'oauth_client_id': config['KEYCLOAK_CLIENT_ID'],
        'oauth_client_secret': config['KEYCLOAK_CLIENT_SECRET'],
    })
    #kwargs['issuer'] = SciTokenIssuer(issuer=config['ISSUER'],
    #                                  audience=config['AUDIENCE'])
    kwargs['issuer'] = None

    login_url = config['BASE_URL']
    if not login_url.endswith('/'):
        login_url += '/'
    login_url += 'login'

    logging.warning(f'debug={config["DEBUG"]}')

    server = RestServer(debug=config['DEBUG'], login_url=login_url, cookie_secret=config['COOKIE_SECRET'])
    server.add_route('/login', OpenIDLoginHandler, login_kwargs)
    server.add_route('/test', TestHandler, kwargs)
    server.add_route(r'/(.*)', Main, kwargs)

    server.startup(address=config['HOST'], port=config['PORT'])

    return server
