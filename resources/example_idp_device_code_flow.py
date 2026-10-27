"""
Example: run a fake upstream IDP plus the real scitoken-issuer, then do the
OAuth2 device code flow (RFC 8628) against the issuer with a swappable client.

FOR LOCAL TESTING ONLY. The fake IDP performs no real authentication: every
login is automatically approved as `--username`.

Flow:
    client  --device code-->  scitoken-issuer  --OIDC login-->  fake IDP
    approve --visit verification_uri_complete--> issuer /login -> IDP /authorize
            -> issuer /login callback -> issuer /device/complete
    client  --poll /token-->  scitoken-issuer  --> tokens

Prerequisites:
    - A running MongoDB (set MONGODB_URL if not mongodb://localhost/scitokens)
    - The scitoken-issuer package installed (`pip install -e .`)

Usage:
    # default scopes, raw requests client
    python resources/example_idp_device_code_flow.py

    # rest_tools client
    python resources/example_idp_device_code_flow.py --client rest_tools

    # use a whitelist instead of POSIX/PAM scope validation
    python resources/example_idp_device_code_flow.py --username alice \\
        --scopes openid storage.read:/data/ana/sub \\
        --allow alice:storage.read:/data/ana

    # same, from a JSON file of {username: [scopes]}
    python resources/example_idp_device_code_flow.py --username alice \\
        --scopes openid storage.read:/data/ana/sub --whitelist-file whitelist.json

Note on default scopes:
    If no `storage.*` scope is requested, the issuer grants
    `storage.{read,modify}:/data/user/{username}` without validation. A later
    refresh grant DOES validate them, so clients that refresh (rest_tools does
    so immediately) fail with `invalid_scope` unless the user/path exists
    locally or is whitelisted, e.g.:
        --allow testuser:storage.read:/data/user/testuser \\
        --allow testuser:storage.modify:/data/user/testuser

Adding a client:
    Write a function matching `DeviceFlowClient` and add it to `CLIENTS`.
    It receives an `approve` callback that plays the role of the user; call it
    with the device authorization response once you have one.

Other issuer settings (KEY_TYPE, POSIX_PATH, ...) are read from the environment
as usual.
"""

import argparse
import asyncio
import base64
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
from typing import Any, Callable
from unittest.mock import patch
import urllib.parse

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import requests
from requests.auth import HTTPBasicAuth
import tornado.httputil
import tornado.web

logger = logging.getLogger('example')

# credentials the issuer uses to talk to the fake IDP
IDP_CLIENT_ID = 'fake-idp-client'
IDP_CLIENT_SECRET = secrets.token_hex(16)

# Callback that "is the user": completes login for a device authorization response.
ApproveFn = Callable[[dict[str, Any]], None]

# Device flow client: (issuer, client_id, client_secret, scopes, approve) -> token response
DeviceFlowClient = Callable[[str, str, str, list[str], ApproveFn], dict[str, Any]]


class DeviceFlowError(Exception):
    """An OAuth2 error returned during the device flow."""
    def __init__(self, error: str, description: str = ''):
        super().__init__(f'{error}: {description}' if description else error)
        self.error = error
        self.description = description


# ---------------------------------------------------------------------------
# Fake IDP
# ---------------------------------------------------------------------------

class FakeIDP:
    """
    Minimal OIDC provider: discovery, JWKS, auto-approving authorize,
    token (authorization_code + refresh_token), userinfo, logout.
    """
    def __init__(self, port: int, username: str):
        self.port = port
        self.address = f'http://localhost:{port}'
        self.username = username

        self.kid = secrets.token_hex(8)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        jwk.update({'kid': self.kid, 'alg': 'RS256', 'use': 'sig'})
        self.jwks = {'keys': [jwk]}

        self.codes: dict[str, dict[str, str]] = {}   # code -> {username, redirect_uri}
        self.refresh_tokens: dict[str, str] = {}     # refresh token -> username
        self.http_server = None

    def make_jwt(self, username: str, expires_in: int) -> str:
        now = int(time.time())
        claims = {
            'iss': self.address,
            'sub': username,
            'aud': IDP_CLIENT_ID,
            'azp': IDP_CLIENT_ID,
            'iat': now,
            'exp': now + expires_in,
            'preferred_username': username,
            'email': f'{username}@example.com',
        }
        return jwt.encode(claims, self.private_key, algorithm='RS256', headers={'kid': self.kid})

    def make_token_response(self, username: str) -> dict[str, Any]:
        # refresh tokens are opaque and rotate on every use
        refresh_token = secrets.token_urlsafe(32)
        self.refresh_tokens[refresh_token] = username
        return {
            'access_token': self.make_jwt(username, 300),
            'id_token': self.make_jwt(username, 300),
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': 300,
            'refresh_expires_in': 86400,
        }

    async def start(self) -> None:
        kwargs = {'idp': self}
        app = tornado.web.Application([
            (r'/.well-known/openid-configuration', IDPWellKnown, kwargs),
            (r'/certs', IDPCerts, kwargs),
            (r'/authorize', IDPAuthorize, kwargs),
            (r'/token', IDPToken, kwargs),
            (r'/userinfo', IDPUserInfo, kwargs),
            (r'/logout', IDPLogout, kwargs),
        ])
        self.http_server = app.listen(self.port, address='localhost')
        logger.info('fake IDP listening at %s', self.address)

    async def stop(self) -> None:
        if self.http_server:
            self.http_server.stop()


class IDPHandler(tornado.web.RequestHandler):
    def initialize(self, idp: FakeIDP):
        self.idp = idp

    def oauth_error(self, status: int, error: str, description: str = '') -> None:
        self.set_status(status)
        self.write({'error': error, 'error_description': description})


class IDPWellKnown(IDPHandler):
    def get(self):
        base = self.idp.address
        self.write({
            'issuer': base,
            'authorization_endpoint': f'{base}/authorize',
            'token_endpoint': f'{base}/token',
            'userinfo_endpoint': f'{base}/userinfo',
            'end_session_endpoint': f'{base}/logout',  # required by rest_tools OpenIDLoginHandler
            'jwks_uri': f'{base}/certs',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'id_token_signing_alg_values_supported': ['RS256'],
        })


class IDPCerts(IDPHandler):
    def get(self):
        self.write(self.idp.jwks)


class IDPAuthorize(IDPHandler):
    def get(self):
        redirect_uri = self.get_query_argument('redirect_uri', '')
        state = self.get_query_argument('state', '')
        if not redirect_uri:
            return self.oauth_error(400, 'invalid_request', 'missing redirect_uri')
        if self.get_query_argument('client_id', '') != IDP_CLIENT_ID:
            args = {'error': 'unauthorized_client', 'state': state}
            return self.redirect(tornado.httputil.url_concat(redirect_uri, args))

        # auto-login: no user interaction, always the configured username
        code = secrets.token_urlsafe(16)
        self.idp.codes[code] = {'username': self.idp.username, 'redirect_uri': redirect_uri}
        logger.info('fake IDP: auto-login as %s', self.idp.username)
        # state must be echoed unchanged; it carries the issuer's XSRF token
        self.redirect(tornado.httputil.url_concat(redirect_uri, {'code': code, 'state': state}))


class IDPToken(IDPHandler):
    def get_client_credentials(self) -> tuple[str, str]:
        auth = self.request.headers.get('Authorization', '')
        if auth.lower().startswith('basic '):
            client_id, _, client_secret = base64.b64decode(auth[6:]).decode('utf-8').partition(':')
            return urllib.parse.unquote(client_id), urllib.parse.unquote(client_secret)
        return self.get_body_argument('client_id', ''), self.get_body_argument('client_secret', '')

    def post(self):
        client_id, client_secret = self.get_client_credentials()
        if client_id != IDP_CLIENT_ID or client_secret != IDP_CLIENT_SECRET:
            return self.oauth_error(401, 'invalid_client')

        match self.get_body_argument('grant_type', ''):
            case 'authorization_code':
                data = self.idp.codes.pop(self.get_body_argument('code', ''), None)
                if not data:
                    return self.oauth_error(400, 'invalid_grant', 'invalid code')
                if data['redirect_uri'] != self.get_body_argument('redirect_uri', ''):
                    return self.oauth_error(400, 'invalid_grant', 'redirect_uri mismatch')
                username = data['username']
            case 'refresh_token':
                username = self.idp.refresh_tokens.pop(self.get_body_argument('refresh_token', ''), None)
                if not username:
                    return self.oauth_error(400, 'invalid_grant', 'invalid refresh_token')
            case other:
                return self.oauth_error(400, 'unsupported_grant_type', other)

        self.write(self.idp.make_token_response(username))


class IDPUserInfo(IDPHandler):
    def get(self):
        auth = self.request.headers.get('Authorization', '')
        try:
            token = auth.split(' ', 1)[1]
            claims = jwt.decode(
                token, self.idp.private_key.public_key(), algorithms=['RS256'],
                options={'verify_aud': False},
            )
        except Exception:
            return self.oauth_error(401, 'invalid_token')
        self.write(claims)


class IDPLogout(IDPHandler):
    def get(self):
        self.write({})


# ---------------------------------------------------------------------------
# Scope whitelist (optional replacement for POSIX/PAM validation)
# ---------------------------------------------------------------------------

class WhitelistValidator:
    """
    Drop-in for `group_validation.Validator`.

    Approves a `storage.*` scope only if the username has a whitelist entry with
    the same permission and a path equal to or above the requested path.

    Note: the issuer only calls this for explicitly requested `storage.*` scopes.
    Requests with none get default `/data/user/{username}` scopes unvalidated.
    """
    def __init__(self, whitelist: dict[str, list[str]], base_path: str = '/'):
        self.whitelist = whitelist
        self.base_path = Path(base_path if base_path else '/')  # read by /healthz

    def __call__(self, username: str = '', scope: str = '') -> bool:
        if not (username and scope.startswith('storage.') and ':' in scope):
            return False
        perm, path = scope.split(':', 1)
        for allowed in self.whitelist.get(username, []):
            a_perm, _, a_path = allowed.partition(':')
            if perm == a_perm and a_path and Path(path).is_relative_to(a_path):
                logger.info('whitelist: allow %s %s', username, scope)
                return True
        logger.info('whitelist: deny %s %s', username, scope)
        return False


def patch_validator(whitelist: dict[str, list[str]]) -> None:
    """
    Replace the issuer's Validator with WhitelistValidator.

    Must run before `Server()` is constructed. Patches the name in the
    `server` module, since it does `from .group_validation import Validator`.
    """
    import scitoken_issuer.server

    def factory(base_path: str, use_ldap: bool = False) -> WhitelistValidator:
        return WhitelistValidator(whitelist, base_path)

    scitoken_issuer.server.Validator = factory  # type: ignore[assignment]


def load_whitelist(allow: list[str], whitelist_file: str | None) -> dict[str, list[str]]:
    """Merge `--allow USER:SCOPE` entries and a `{user: [scopes]}` JSON file."""
    whitelist: dict[str, list[str]] = {}
    if whitelist_file:
        with open(whitelist_file) as f:
            for user, scopes in json.load(f).items():
                whitelist.setdefault(user, []).extend(scopes)
    for entry in allow:
        user, sep, scope = entry.partition(':')  # split on the first ':' only
        if not sep or not scope:
            raise ValueError(f'invalid --allow entry (expected USER:SCOPE): {entry}')
        whitelist.setdefault(user, []).append(scope)
    return whitelist


# ---------------------------------------------------------------------------
# Server plumbing
# ---------------------------------------------------------------------------

class LoopThread:
    """A dedicated asyncio event loop in a background thread."""
    def __init__(self, name: str):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, name=name, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro_fn: Callable[[], Any], timeout: float = 30) -> Any:
        """Run a coroutine function on this loop and wait for its result."""
        return asyncio.run_coroutine_threadsafe(coro_fn(), self.loop).result(timeout)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]


def register_client(issuer: str, scopes: list[str]) -> dict[str, Any]:
    """Dynamically register a device-flow client with the issuer."""
    meta = {
        'client_name': 'example-device-flow',
        'grant_types': ['urn:ietf:params:oauth:grant-type:device_code'],
        'scope': ' '.join(scopes),
    }
    r = requests.post(f'{issuer}/client', json=meta, timeout=10)
    r.raise_for_status()
    return r.json()


def delete_client(data: dict[str, Any]) -> None:
    r = requests.delete(
        data['registration_client_uri'],
        headers={'Authorization': f'Bearer {data["registration_access_token"]}'},
        timeout=10,
    )
    r.raise_for_status()


# ---------------------------------------------------------------------------
# User approval (swappable)
# ---------------------------------------------------------------------------

def approve_with_requests(device_response: dict[str, Any]) -> None:
    """
    Play the user: visit verification_uri_complete and follow redirects
    through the issuer login and the (auto-approving) fake IDP.
    """
    url = device_response.get('verification_uri_complete') or \
        f'{device_response["verification_uri"]}?user_code={device_response["user_code"]}'
    logger.info('approving device code %s at %s', device_response['user_code'], url)
    with requests.Session() as session:
        r = session.get(url, timeout=30)
        logger.debug('approval redirects: %r', [h.url for h in r.history])
        r.raise_for_status()
        if 'authorization complete' not in r.text.lower():
            raise RuntimeError(f'device approval did not complete: {r.url}')


# ---------------------------------------------------------------------------
# Device flow clients (swappable)
# ---------------------------------------------------------------------------

def client_raw_requests(
    issuer: str, client_id: str, client_secret: str, scopes: list[str], approve: ApproveFn,
) -> dict[str, Any]:
    """Reference RFC 8628 implementation using plain requests."""
    meta = requests.get(f'{issuer}/.well-known/openid-configuration', timeout=10).json()
    auth = HTTPBasicAuth(client_id, client_secret)

    # 1. device authorization request
    r = requests.post(
        meta['device_authorization_endpoint'],
        data={'client_id': client_id, 'scope': ' '.join(scopes)},
        auth=auth, timeout=10,
    )
    if not r.ok:
        err = r.json()
        raise DeviceFlowError(err.get('error', str(r.status_code)), err.get('error_description', ''))
    device = r.json()

    # 2. user approves (normally on another device)
    approve(device)

    # 3. poll the token endpoint
    interval = float(device.get('interval', 5))
    deadline = time.monotonic() + float(device.get('expires_in', 600))
    while time.monotonic() < deadline:
        time.sleep(interval)
        r = requests.post(
            meta['token_endpoint'],
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device['device_code'],
                'client_id': client_id,
            },
            auth=auth, timeout=10,
        )
        if r.ok:
            return r.json()
        err = r.json()
        match err.get('error'):
            case 'authorization_pending':
                continue
            case 'slow_down':
                interval += 5
                continue
            case error:
                raise DeviceFlowError(error or str(r.status_code), err.get('error_description', ''))
    raise DeviceFlowError('expired_token', 'device code expired while polling')


def client_rest_tools(
    issuer: str, client_id: str, client_secret: str, scopes: list[str], approve: ApproveFn,
) -> dict[str, Any]:
    """rest_tools DeviceGrantAuth, the client used by the test suite."""
    from rest_tools.client import DeviceGrantAuth

    # DeviceGrantAuth shows the user prompt via this private function; hook it.
    with patch('rest_tools.client.device_client._print_qrcode', approve):
        rc = DeviceGrantAuth(
            issuer, issuer,
            client_id=client_id, client_secret=client_secret,
            scopes=scopes, retries=0, timeout=10,
        )
    # _openid_token() runs a refresh grant against the issuer for an access token
    return {'access_token': rc._openid_token(), 'refresh_token': rc.refresh_token}


CLIENTS: dict[str, DeviceFlowClient] = {
    'requests': client_raw_requests,
    'rest_tools': client_rest_tools,
}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_tokens(issuer: str, tokens: dict[str, Any]) -> dict[str, Any]:
    """Validate the access token signature against the issuer JWKS and print claims."""
    access_token = tokens['access_token']
    jwks_client = jwt.PyJWKClient(f'{issuer}/certs')
    key = jwks_client.get_signing_key_from_jwt(access_token)
    alg = jwt.get_unverified_header(access_token)['alg']
    claims = jwt.decode(
        access_token, key, algorithms=[alg], issuer=issuer,
        options={'verify_aud': False},
    )
    print('Access token verified. Claims:')
    for name in ('iss', 'sub', 'scope', 'aud', 'azp', 'exp'):
        if name in claims:
            print(f'  {name:6} {claims[name]}')
    print(f'Refresh token present: {bool(tokens.get("refresh_token"))}')
    return claims


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--username', default='testuser', help='user the fake IDP logs in as')
    parser.add_argument('--scopes', nargs='*', default=['openid'], help='scopes to request')
    parser.add_argument('--client', choices=sorted(CLIENTS), default='requests', help='device flow client')
    parser.add_argument('--idp-port', type=int, default=0, help='fake IDP port (default: random)')
    parser.add_argument('--issuer-port', type=int, default=0, help='issuer port (default: random)')
    parser.add_argument('--allow', action='append', default=[], metavar='USER:SCOPE',
                        help='whitelist entry, e.g. alice:storage.read:/data/ana (repeatable)')
    parser.add_argument('--whitelist-file', help='JSON file of {username: [scopes]}')
    parser.add_argument('--log-level', default='ERROR', help='python log level')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=args.log_level.upper(), format='%(asctime)s %(levelname)s %(name)s - %(message)s')
    logger.setLevel(min(logging.INFO, logging.getLogger().level))

    try:
        whitelist = load_whitelist(args.allow, args.whitelist_file)
    except (ValueError, OSError) as e:  # json.JSONDecodeError is a ValueError
        print(f'Invalid whitelist: {e}', file=sys.stderr)
        return 2

    idp_port = args.idp_port or get_free_port()
    issuer_port = args.issuer_port or get_free_port()
    issuer = f'http://localhost:{issuer_port}'

    # config.ENV is built at import time, so set the environment BEFORE importing scitoken_issuer
    os.environ.update({
        'IDP_ADDRESS': f'http://localhost:{idp_port}',
        'IDP_CLIENT_ID': IDP_CLIENT_ID,
        'IDP_CLIENT_SECRET': IDP_CLIENT_SECRET,
        'HOST': 'localhost',
        'PORT': str(issuer_port),
        'ISSUER_ADDRESS': issuer,
        'DEVICE_CODE_POLLING_INTERVAL': '1',
        'LOG_LEVEL': args.log_level.upper(),
    })
    from scitoken_issuer.server import Server

    if whitelist:
        patch_validator(whitelist)

    idp = FakeIDP(idp_port, args.username)
    idp_loop = LoopThread('fake-idp')
    issuer_loop = LoopThread('issuer')
    server: Server | None = None
    client_data = None
    try:
        # the IDP must be up first: Server() does OIDC discovery against it
        idp_loop.run(idp.start)

        async def start_issuer() -> Server:
            s = Server()
            await s.start()
            return s
        server = issuer_loop.run(start_issuer)
        logger.info('issuer listening at %s', issuer)

        client_data = register_client(issuer, args.scopes)
        print(f'Running device flow with client "{args.client}" as user "{args.username}", scopes {args.scopes}', flush=True)
        tokens = CLIENTS[args.client](
            issuer, client_data['client_id'], client_data['client_secret'],
            args.scopes, approve_with_requests,
        )
        verify_tokens(issuer, tokens)
        return 0
    except Exception as e:
        logger.debug('device flow failed', exc_info=True)
        print(f'Device flow FAILED: {e!r}', file=sys.stderr)
        if e.__cause__:
            print(f'  caused by: {e.__cause__!r}', file=sys.stderr)
        return 1
    finally:
        if client_data:
            try:
                delete_client(client_data)
            except Exception:
                logger.warning('failed to delete client', exc_info=True)
        if server:
            issuer_loop.run(server.stop)
        idp_loop.run(idp.stop)
        issuer_loop.close()
        idp_loop.close()


if __name__ == '__main__':
    sys.exit(main())
