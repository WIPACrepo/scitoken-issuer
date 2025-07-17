# type: ignore[misc]
# ignore complaints about get/set cookie and the base handler

from collections.abc import Callable
#import importlib.resources
import json
import logging
#import os
import secrets
import time
from typing import Any
import urllib.parse
import uuid

import jwt
import pymongo.errors
import tornado.escape
from tornado.web import HTTPError
import tornado.httpclient
from tornado.httputil import url_concat
from rest_tools.server import (
    RestHandler,
    RestHandlerSetup,
    RestServer,
    OpenIDLoginHandler,
    catch_error
)
from rest_tools.utils.auth import Auth, OpenIDAuth

from . import __version__ as version
from . import config
from .state import State
from .group_validation import Validator
from .utils import basic_decode


logger = logging.getLogger('server')


class OAuthError(HTTPError):
    def __init__(self, status_code: int = 400, error: str = '', description: str = ''):
        super().__init__(status_code=status_code)
        self.error = error
        self.description = description


class TokenMixin:
    """Store/load current user's `OpenIDLoginHandler` tokens in DB."""
    auth: OpenIDAuth
    state: State
    get_secure_cookie: Callable[[str], str]
    set_secure_cookie: Callable[..., None]
    clear_cookie: Callable[[str], None]


    async def get_idp_tokens(self, username: str) -> dict[str, Any]:
        """
        Verify the username from the IdP token.

        Runs the refresh flow against the IdP to check the user is still valid.
        """
        refresh_token = await self.state.get_identity_for_sub(username)

        http = tornado.httpclient.AsyncHTTPClient()
        body = {
            'client_id': config.ENV.IDP_CLIENT_ID,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        # get a new refresh token
        try:
            logger.debug('do refresh at %s', self.auth.token_url)
            response = await http.fetch(
                self.auth.token_url,
                method='POST',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                body=urllib.parse.urlencode(body),
                auth_username=config.ENV.IDP_CLIENT_ID,
                auth_password=config.ENV.IDP_CLIENT_SECRET,
            )
            ret = tornado.escape.json_decode(response.body)
            refresh_token = ret['refresh_token']
        except Exception:
            logger.info('IdP refresh_token for %s cannot be renewed', username, exc_info=True)
            raise

        await self.state.put_identity_for_sub(username, refresh_token)
        return ret

    async def get_idp_username(self, username: str | None = None) -> str | None:
        """
        Verify the username from the IdP token.

        Runs the refresh flow against the IdP to check the user is still valid.
        """
        try:
            if not username:
                username = self.get_secure_cookie('scitoken_username')
                if not username:
                    return None
                if isinstance(username, bytes):
                    username = username.decode('utf-8')

            await self.get_idp_tokens(username)
            return username

        except Exception:
            logger.debug('failed auth', exc_info=True)
        return None

    async def store_tokens(
        self,
        access_token,
        access_token_exp,
        refresh_token=None,
        refresh_token_exp=None,
        user_info=None,
        user_info_exp=None,
    ):
        """
        Store jwt tokens and user info from OpenID-compliant auth source.

        Args:
            access_token (str): jwt access token
            access_token_exp (int): access token expiration in seconds
            refresh_token (str): jwt refresh token
            refresh_token_exp (int): refresh token expiration in seconds
            user_info (dict): user info (from id token or user info lookup)
            user_info_exp (int): user info expiration in seconds
        """
        if not user_info:
            user_info = self.auth.validate(access_token)
        username = user_info.get('preferred_username')
        if not username:
            username = user_info.get('upn')
        if not username:
            raise HTTPError(400, reason='no username in token')
        if not refresh_token:
            raise HTTPError(400, reason='no refresh token')

        await self.state.put_identity_for_sub(username, refresh_token)
        self.set_secure_cookie('scitoken_username', username, expires_days=30)

    async def clear_tokens(self):
        """
        Clear token data, usually on logout.
        """
        username = self.get_secure_cookie('scitoken_username')
        if not username:
            return
        if isinstance(username, bytes):
            username = username.decode('utf-8')

        await self.state.delete_identity(username)
        self.clear_cookie('scitoken_username')


class DisableXSRF:
    def check_xsrf_cookie(self):
        """
        Override this to not complain about xsrf cookies on API handlers.
        """
        pass


class BaseHandler(TokenMixin, RestHandler):

    def initialize(self, state, validate, *args, **kwargs):
        self.state = state
        self.validate = validate
        self.issuer = config.ENV.ISSUER_ADDRESS.rstrip('/')
        logger.info('issuer: %s', self.issuer)
        return super().initialize(*args, **kwargs)

    def set_default_headers(self):
        super()
        self._headers['Cache-Control'] = 'no-store'
        self._headers['Pragma'] = 'no-cache'

    def get_current_user(self):
        """
        Get client_id / client_secret.
        """
        self.client_id = None
        try:
            type, token = self.request.headers['Authorization'].split(' ', 1)
            if type.lower() != 'basic':
                raise Exception('bad header type')
            logger.debug('token: %r', token)
            username, password = basic_decode(token)
            self.client_secret = password
            return username
        # Auth Failed
        except Exception:
            logger.warning('cannot get basic auth', exc_info=True)
            # try POST
            if self.request.method == 'POST':
                try:
                    client_id = self.get_body_argument('client_id', '')
                    client_secret = self.get_body_argument('client_secret', '')
                    if not client_id or not client_secret:
                        raise Exception('missing client_id or client_secret')
                    self.client_secret = client_secret
                    return client_id
                except Exception:
                    logger.warning('cannot get client_id and client_secret from post args')
        return None

    def send_error(self, status_code: int = 400, **kwargs: Any):
        if self._headers_written:
            return
        self.clear()
        self.set_status(status_code)
        try:
            self.write_error(status_code, **kwargs)
        except Exception:
            logger.error("Uncaught exception in write_error", exc_info=True)
            self.finish()

    def write_error(self, status_code=500, **kwargs):
        """Write out custom error json."""
        data : dict[str, str|int] = {
            'code': status_code,
        }
        if "exc_info" in kwargs:
            exception = kwargs["exc_info"][1]
            if isinstance(exception, OAuthError):
                data['error'] = exception.error
                data['error_description'] = exception.description
        self.write(data)
        self.finish()

    def _process_scopes(self, username: str, scopes: str) -> str:
        """
        Process the scopes in a token request. Validate the storage.* scopes.
        """
        requested_scopes = []
        final_scopes = []
        for x in scopes.split():
            if x.startswith('storage.'):
                requested_scopes.append(x)
            else:
                final_scopes.append(x)
        logging.debug('requesting scopes: %r', requested_scopes)
        try:
            if requested_scopes:
                potential_scopes = []
                for s in requested_scopes:
                    if self.validate(username=username, scope=s):
                        potential_scopes.append(s)
                    else:
                        raise Exception(f'invalid scope for user {username}: {s}')
                logging.debug('valid scopes: %s', scopes)
            else:
                # default case
                potential_scopes = [
                    f'storage.read:/data/user/{username}',
                    f'storage.modify:/data/user/{username}',
                ]
        except Exception:
            logging.info('failed to get scopes', exc_info=True)
            raise OAuthError(400, error='invalid_scope', description='invalid scopes')
        final_scopes.extend(potential_scopes)
        return ' '.join(final_scopes)


class Main(BaseHandler):
    """The main page"""
    def get(self):
        self.write({})


class WellKnown(BaseHandler):
    """
    OpenID Connect Discovery.

    Also RFC8414, OAuth 2.0 Authorization Server Metadata, which came later.

    https://openid.net/specs/openid-connect-discovery-1_0.html
    """
    async def get(self):
        base = self.issuer
        content = {
            'issuer': base,
            'authorization_endpoint': f'{base}/authorize',
            'token_endpoint': f'{base}/token',
            'userinfo_endpoint': f'{base}/userinfo',
            'jwks_uri': f'{base}/certs',
            'registration_endpoint': f'{base}/client/registration',
            'device_authorization_endpoint': f'{base}/device/code',
            'scopes_supported': [
                'openid',
                'profile',
                'email',
                'phone',
                'offline_access',
                'storage.read',
                'storage.create',
                'storage.modify',
            ],
            'response_types_supported': [
                'code',
                'code id_token',
                'id_token',
            ],
            'grant_types_supported': [
                'authorization_code',
                'refresh_token',
                'urn:ietf:params:oauth:grant-type:device_code',
            ],
            #'code_challenge_methods_supported': [
            #    'plain',
            #    'S256',
            #],
            'subject_types_supported': ['public'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
            'token_endpoint_auth_signing_alg_values_supported': config.DEFAULT_KEY_ALGORITHMS,
            'userinfo_signing_alg_values_supported': config.DEFAULT_KEY_ALGORITHMS,
            'id_token_signing_alg_values_supported': config.DEFAULT_KEY_ALGORITHMS,
            #'request_object_signing_alg_values_supported':
            #    ['none'],
            'claims_supported': [
                'aud',
                'sub',
                'iss',
                'auth_time',
                'preferred_username',
            ],
        }
        self.write(content)


class Certs(BaseHandler):
    """
    JWKS certificates.
    """
    async def get(self):
        ret = await self.state.get_jwks()
        self.write(ret)


class Token(DisableXSRF, BaseHandler):
    """
    Handle OAuth2 token requests.
    """
    async def post(self):
        logging.info('token!')
        # check client id and secret
        client_id = self.current_user
        client_secret = self.client_secret
        if not client_id or not client_secret:
            raise OAuthError(401, error='invalid_client', description='missing client_id or client_secret')

        client = await self.state.get_client(client_id)
        if client.get('client_secret', '') != client_secret:
            raise OAuthError(400, error='invalid_client', description='missing client_id or client_secret')

        code_challenge = self.get_body_argument('code_challenge', '')
        if code_challenge:
            raise OAuthError(400, error='unsupported_grant_type', description='code_challenge unsupported')

        # do things based on grant type
        grant_type = self.get_body_argument('grant_type', '')
        logger.info('token grant type: %s', grant_type)
        match grant_type:
            case 'authorization_code':
                auth_code = self.get_body_argument('code', '')
                if not auth_code:
                    raise OAuthError(400, error='invalid_request', description='missing code')
                
                try:
                    ret = await self.state.get_auth_code(auth_code)
                except KeyError:
                    raise OAuthError(400, error='invalid_request', description='invalid code')

                username = ret['username']
                scope = ret['scope']
                if ret['expiration'] < time.time():
                    raise OAuthError(400, error='invalid_request', description='invalid code')
                if ret['redirect']:
                    redirect = self.get_body_argument('redirect_uri', '')
                    if not redirect or redirect != ret['redirect']:
                        raise OAuthError(400, error='invalid_request', description='invalid redirect')

                # auth code must only be used once                
                await self.state.delete_auth_code(auth_code)

            case 'refresh_token':
                refresh_token = self.get_body_argument('refresh_token', '')
                if not refresh_token:
                    raise OAuthError(400, error='invalid_request', description='missing refresh_token')
                scope = self.get_body_argument('scope', '')

                # validate refresh token
                all_keys = await self.state.get_jwks()
                logger.debug('all_keys: %r', all_keys)
                keys = {
                    k.key_id: k.key for k in jwt.PyJWKSet.from_dict(all_keys).keys
                }
                try:
                    auth = OpenIDAuth('', provider_info={'jwks_uri': ''}, public_keys=keys, algorithms=config.DEFAULT_KEY_ALGORITHMS)
                    data = auth.validate(refresh_token)
                    username = data['idp_username']
                except Exception:
                    logger.info('error validating refresh token', exc_info=True)
                    raise OAuthError(400, error='invalid_grant', description='invalid refresh token')

                # check against IdP
                username = await self.get_idp_username(username)
                if not username:
                    raise OAuthError(400, error='invalid_grant', description='invalid IdP token')

            case 'urn:ietf:params:oauth:grant-type:device_code':
                device_code = self.get_body_argument('device_code', '')
                if not device_code:
                    raise OAuthError(400, error='invalid_request', description='missing device_code')
                
                # validate device code
                try:
                    ret = await self.state.get_device_code(device_code)
                    scope = ret.get('scope', '')
                except KeyError:
                    raise OAuthError(400, error='expired_token')
                if ret['client_id'] != client_id:
                    raise OAuthError(400, error='invalid_client', description='invalid client_id')
                if ret['status'] == 'new':
                    raise OAuthError(400, error='authorization_pending')
                elif ret['status'] == 'denied':
                    raise OAuthError(400, error='access_denied')
                elif ret['status'] == 'verified':
                    logger.info('successful device token flow for %s', client_id)
                    await self.state.delete_device_code(ret['device_code'])
                else:
                    raise OAuthError(400, error='expired_token')

                if not ret['username']:
                    raise OAuthError(400, error='invalid_grant', description='invalid IdP token')
                username = ret['username']

            case _:
                raise OAuthError(400, error='unsupported_grant_type')

        # check scopes
        scope = self._process_scopes(username, scope)
        logging.info('create token for user %s, scope %s', username, scope)

        # grant token
        current_key = await self.state.get_current_key()
        auth = Auth(
            secret=current_key['private_key'],
            audience=config.ENV.AUDIENCE,
            issuer=config.ENV.ISSUER_ADDRESS,
            algorithm=config.ENV.KEY_TYPE,
            expiration=config.ENV.REFRESH_TOKEN_EXPIRATION,
            expiration_temp=config.ENV.ACCESS_TOKEN_EXPIRATION,
        )
        access_token = auth.create_token(
            subject=username,
            payload={
                'aud': config.ENV.AUDIENCE,
                config.ENV.IDP_USERNAME_CLAIM: username,
                'scope': scope,
            },
            headers={'kid': current_key['kid']},
        )
        refresh_token = auth.create_token(
            subject=username,
            type='refresh',
            payload={
                'aud': config.ENV.ISSUER_ADDRESS,
                config.ENV.IDP_USERNAME_CLAIM: username,
                'idp_username': username,
                'scope': scope,
            },
            headers={'kid': current_key['kid']},
        )
        self.write({
            'access_token': access_token,
            'token_type': 'bearer',
            'expires_in': config.ENV.ACCESS_TOKEN_EXPIRATION,
            'refresh_token': refresh_token,
            'scope': scope,
        })


class Authorize(BaseHandler):
    """
    Handle OAuth2 authorization requests.
    """
    async def get(self):
        logging.info('authorize!')
        # check client id and secret
        client_id = self.get_query_argument('client_id', '')
        if not client_id:
            raise OAuthError(401, error='invalid_client', description='missing client_id')
        client = await self.state.get_client(client_id)
        if not client:
            raise OAuthError(401, error='invalid_client', description='invalid client_id')

        # do things based on response type
        response_type = self.get_query_argument('response_type', '')
        logger.info('response type: %s', response_type)
        if response_type != 'code':
            raise OAuthError(400, error='unsupported_response_type')

        redirect = self.get_query_argument('redirect_uri', None)
        if not client['redirect_uris'] and not redirect:
            raise OAuthError(400, error='invalid_request', description='redirect_uris is required')

        state = {
            'client_id': client_id,
            'scope': self.get_query_argument('scope', None),
            'state': self.get_query_argument('state', None),
        }
        if redirect:
            state['redirect'] = redirect

        self.redirect(url_concat('/login', {'next': '/authorize/complete', 'state': tornado.escape.json_encode(state)}))


class AuthorizeComplete(BaseHandler):
    """
    Handle OAuth2 authorization request completions.
    """
    @catch_error
    async def get(self):
        # get username
        username = await self.get_idp_username()
        logger.info('authorize complete for username %s', username)
        if not username:
            raise OAuthError(400, error='invalid_request', description='invalid IdP username')

        state = tornado.escape.json_decode(self.get_query_argument('state', '{}'))
        redirect_uri = state.get('redirect', None)

        auth_code = uuid.uuid4().hex
        await self.state.add_auth_code(
            code=auth_code,
            client_id=state['client_id'],
            scope=state['scope'],
            username=username,
            redirect=redirect_uri,
        )

        uri = redirect_uri
        if not uri:
            client = await self.state.get_client(state['client_id'])
            if not client:
                raise OAuthError(401, error='invalid_client', description='invalid client_id')
            try:
                uri = client['redirection_uris'][0]
            except Exception:
                raise OAuthError(401, error='invalid_request', description='unknown redirect_uri')

        args = {
            'code': auth_code
        }
        if state['state'] is not None:
            args['state'] = state['state']
        if uri:
            self.redirect(url_concat(uri, args))
        else:
            self.write("authorization successful")


class UserInfo(BaseHandler):
    """
    Handle OAuth2 user info requests.
    """
    async def get(self):
        # get token from auth
        try:
            type, token = self.request.headers['Authorization'].split(' ', 1)
            if type.lower() != 'bearer':
                raise Exception('bad header type')
            logger.debug('token: %r', token)
        except Exception:
            raise OAuthError(401, error='invalid_request', description='invalid authorization')

        # validate refresh token
        all_keys = await self.state.get_jwks()
        logger.debug('all_keys: %r', all_keys)
        keys = {
            k.key_id: k.key for k in jwt.PyJWKSet.from_dict(all_keys).keys
        }
        try:
            auth = OpenIDAuth('', provider_info={'jwks_uri': ''}, public_keys=keys, algorithms=config.DEFAULT_KEY_ALGORITHMS)
            data = auth.validate(token)
            username = data['sub']
        except Exception:
            logger.info('error validating token', exc_info=True)
            raise OAuthError(400, error='invalid_request', description='invalid authorization')

        # ask IdP for user info
        tokens = await self.get_idp_tokens(username)
        access_token = tokens.get('access_token', None)
        if not access_token:
            raise OAuthError(400, error='invalid_request', description='invalid authorization')

        http = tornado.httpclient.AsyncHTTPClient()
        # get a new refresh token
        try:
            logger.debug('do refresh at %s', self.auth.token_url)
            response = await http.fetch(
                self.auth.provider_info['userinfo_endpoint'],
                method='GET',
                headers={
                    'Authorization': f'bearer {access_token}'
                },
            )
            data = tornado.escape.json_decode(response.body)
        except Exception:
            logger.info('IdP user_info for %s failed', username, exc_info=True)
            raise OAuthError(400, error='invalid_request', description='invalid authorization')
        # put our own sub in
        data['sub'] = username
        self.write(data)


class DeviceCode(DisableXSRF, BaseHandler):
    """
    Handle OAuth2 device code requests.
    """
    async def post(self):
        logging.info('device code!')
        # check client id and secret
        client_id = self.current_user
        client_secret = self.client_secret
        if not client_id or not client_secret:
            raise OAuthError(401, error='invalid_client', description='missing client_id or client_secret')
    
        client = await self.state.get_client(client_id)
        if client.get('client_secret', '') != client_secret:
            raise OAuthError(400, error='invalid_client', description='missing client_id or client_secret')

        scope = self.get_body_argument('scope', '')
        code_challenge = self.get_body_argument('code_challenge', '')
        if code_challenge:
            raise OAuthError(400, error='unsupported_grant_type', description='code_challenge unsupported')

        device_code = secrets.token_hex(16)
        user_code = secrets.token_hex(4)
        await self.state.add_device_code(
            device_code=device_code,
            user_code=user_code,
            client_id=client_id,
            scope=scope,
        )
        ret = {
            'device_code': device_code,
            'user_code': user_code,
            'verification_uri': f'{self.issuer}/device/verify',
            'verification_uri_complete': f'{self.issuer}/device/verify?user_code={user_code}',
            'expires_in': config.ENV.DEVICE_CODE_EXPIRATION,
            'interval': config.ENV.DEVICE_CODE_POLLING_INTERVAL,
        }
        self.write(ret)


class DeviceCodeVerify(BaseHandler):
    """
    Handle OAuth2 device code verification.
    """
    async def do_code(self, user_code):
        logging.info('device code verification!')
        if not user_code:
            # user enters code in browser
            self.write(
            """
            <html>
            <head></head>
            <body>
            <h1>SciToken Issuer</h1>
            <h2>Device code authorization</h2>
            <form>
            <label>Enter user code:</label>
            <input type="text" name="user_code" />
            </form>
            </body>
            </html>
            """)

        else:
            # user has entered the code
            try:
                await self.state.get_device_code_by_user(user_code)
            except KeyError:
                raise OAuthError(400, error='invalid_request', description='invalid user_code')

            # now check with IdP
            self.redirect(url_concat('/login', {'next': '/device/complete', 'state': user_code}))

    async def get(self):
        await self.do_code(self.get_query_argument('user_code', ''))

    async def post(self):
        await self.do_code(self.get_body_argument('user_code', ''))


class DeviceCodeComplete(BaseHandler):
    """
    Handle OAuth2 device code verification.
    """
    async def get(self):
        user_code = self.get_query_argument('state', '')
        if not user_code:
            raise OAuthError(400, error='invalid_request', description='invalid user_code')
        try:
            data = await self.state.get_device_code_by_user(user_code)
        except KeyError:
            raise OAuthError(400, error='invalid_request', description='invalid user_code')

        # get username
        username = await self.get_idp_username()
        logger.info('device code complete for user_code %s, username %s', user_code, username)
        if not username:
            raise OAuthError(400, error='invalid_grant', description='invalid IdP username')

        # update the device code status
        await self.state.update_device_code(data['device_code'], 'verified', username=username)

        self.write(
        """
        <html>
        <head></head>
        <body>
        <h1>SciToken Issuer</h1>
        <h2>Device code authorization complete!</h2>
        <p>You may now close this page.</p>
        </body>
        </html>
        """)


class ClientRegistration(DisableXSRF, BaseHandler):
    """
    Handle OAuth2 / OpenID Connnect client registration requests.
    """
    async def post(self):
        data = json.loads(self.request.body)

        if 'client_name' not in data:
            raise OAuthError(400, error='invalid_client_metadata', description='client_name is not included')

        if 'redirect_uris' not in data:
            data['redirect_uris'] = []

        if 'grant_types' not in data:
            data['grant_types'] = ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code']
        
        if 'response_types' not in data:
            data['response_types'] = 'code'

        data['client_id'] = uuid.uuid4().hex
        data['client_secret'] = secrets.token_hex(16)
        now = int(time.time())
        data['client_id_issued_at'] = now
        data['client_secret_expires_at'] = now + config.ENV.CLIENT_REGISTRATION_EXPIRATION
        data['registration_client_uri'] = config.ENV.ISSUER_ADDRESS + '/client/'+data['client_id']
        data['registration_access_token'] = secrets.token_hex(32)
        logger.debug('client registration: %r', data)

        try:
            await self.state.add_client(data)
        except pymongo.errors.DuplicateKeyError:
            raise OAuthError(400, error='invalid_client_metadata', description='client already registered')
        else:
            self.set_status(201)
            logger.debug('returing: %r', data)
            self.write(data)


class ClientDetails(DisableXSRF, BaseHandler):
    """
    Handle OAuth2 / OpenID Connnect client registration information and deletion.
    """
    def get_access_token(self):
        try:
            type, token = self.request.headers['Authorization'].split(' ', 1)
            if type.lower() != 'bearer':
                raise Exception('bad header type')
            logger.debug('token: %r', token)
            return token
        # Auth Failed
        except Exception:
            logger.warning('cannot get token', exc_info=True)
            raise HTTPError(401, reason='Unauthorized')

    async def get(self, client_id):
        token = self.get_access_token()
        try:
            ret = await self.state.get_client(client_id)
        except KeyError:
            raise HTTPError(401, reason='Unauthorized')
        else:
            if ret['registration_access_token'] != token:
               raise HTTPError(403, reason='Forbidden')
            self.write(ret)

    async def delete(self, client_id):
        token = self.get_access_token()
        try:
            ret = await self.state.get_client(client_id)
        except KeyError:
            raise HTTPError(401, reason='Unauthorized')
        else:
            if ret['registration_access_token'] != token:
               raise HTTPError(403, reason='Forbidden')
        try:
            await self.state.delete_client(client_id)
        except Exception:
            raise HTTPError(500)
        self.set_status(204)


class Login(TokenMixin, OpenIDLoginHandler):  # type: ignore
    def initialize(self, state, *args, **kwargs):
        self.state = state
        return super().initialize(*args, **kwargs)
    
    def get_current_user(self):
        return None


class Health(BaseHandler):
    """
    Health handler.
    
    Mostly for Kubernetes health checks.
    """
    async def get(self):
        ret = {}
        try:
            self.validate.base_path.exists()
            ret['posix_path'] = True
        except Exception:
            self.set_status(500)
            ret['posix_path'] = False
        try:
            ret2 = await self.state.get_jwks()
            if len(ret2['keys']) < 1:
                raise Exception('no jwks')
            ret['jwks'] = True
        except Exception:
            self.set_status(500)
            ret['jwks'] = False
        self.write(ret)


class Server:
    def __init__(self):
        handler_config = {
            'debug': config.ENV.DEBUG,
            'server_header': f'SciToken Issuer {version}',
            'auth': {
                'openid_url': config.ENV.IDP_ADDRESS,
            }
        }
        kwargs = RestHandlerSetup(handler_config)
        kwargs['route_stats'] = None  # disable route stats for more speed
        self.state = State()
        kwargs['state'] = self.state

        login_kwargs = kwargs.copy()
        login_kwargs['oauth_client_id'] = config.ENV.IDP_CLIENT_ID
        login_kwargs['oauth_client_secret'] = config.ENV.IDP_CLIENT_SECRET
        login_kwargs['oauth_client_scope'] = 'profile email'

        kwargs['validate'] = Validator(base_path=config.ENV.POSIX_PATH, use_ldap=config.ENV.USE_LDAP)

        cookie_secret = config.ENV.COOKIE_SECRET
        log_cookie_secret = cookie_secret[:4] + 'X'*(len(cookie_secret)-8) + cookie_secret[-4:]
        logger.info('using supplied cookie secret %r', log_cookie_secret)

        # static_path = str(importlib.resources.files('iceprod.website')/'data'/'www')
        # if static_path is None or not os.path.exists(static_path):
        #     logger.info('static path: %r',static_path)
        #     raise Exception('bad static path')
        # template_path = str(importlib.resources.files('iceprod.website')/'data'/'www_templates')
        # if template_path is None or not os.path.exists(template_path):
        #     logger.info('template path: %r',template_path)
        #     raise Exception('bad template path')

        server = RestServer(
            debug=config.ENV.DEBUG,
            login_url=f'{config.ENV.ISSUER_ADDRESS}/login',
            cookie_secret=cookie_secret,
            # template_path=template_path,
            # static_path=static_path,
        )

        server.add_route('/', Main, kwargs)
        server.add_route('/.well-known/openid-configuration', WellKnown, kwargs)
        server.add_route('/.well-known/oauth-authorization-server', WellKnown, kwargs)
        server.add_route('/certs', Certs, kwargs)
        server.add_route('/token', Token, kwargs)
        server.add_route('/authorize', Authorize, kwargs)
        server.add_route('/authorize/complete', AuthorizeComplete, kwargs)
        server.add_route('/userinfo', UserInfo, kwargs)
        server.add_route('/device/code', DeviceCode, kwargs)
        server.add_route('/device/verify', DeviceCodeVerify, kwargs)
        server.add_route('/device/complete', DeviceCodeComplete, kwargs)
        server.add_route('/client', ClientRegistration, kwargs)
        server.add_route('/login', Login, login_kwargs)
        server.add_route(r'/client/(.*)', ClientDetails, kwargs)
        server.add_route('/healthz', Health, kwargs)

        server.startup(address=config.ENV.HOST, port=config.ENV.PORT)

        self.server = server

    async def start(self):
        # make sure we have a private key
        await self.state.get_current_key()

    async def stop(self):
        await self.server.stop()
