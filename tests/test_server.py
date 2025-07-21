import asyncio
from contextlib import asynccontextmanager
from html import unescape
from functools import partial
import logging
import threading
import multiprocessing
import os
from unittest.mock import patch, Mock
import urllib.parse

import bs4
import jwt
from krs import bootstrap
from krs.token import get_token
from krs.users import create_user, delete_user, set_user_password
import pytest
import pytest_asyncio
from rest_tools.client import RestClient, DeviceGrantAuth
from rest_tools.utils import OpenIDAuth
import requests
from requests.auth import HTTPBasicAuth
import requests.exceptions

import scitoken_issuer.config
import scitoken_issuer.server
from scitoken_issuer.server import Server

from .util import env


@pytest.fixture(scope='module')
def keycloak_bootstrap(monkeysession, port):
    monkeysession.setenv('KEYCLOAK_REALM', 'testrealm')
    monkeysession.setenv('KEYCLOAK_CLIENT_ID', 'testclient')
    monkeysession.setenv('USERNAME', 'admin')
    monkeysession.setenv('PASSWORD', 'admin')
    if 'KEYCLOAK_URL' not in os.environ:
        monkeysession.setenv('KEYCLOAK_URL', 'http://localhost:8080')

    secret = bootstrap.bootstrap()
    monkeysession.setenv('KEYCLOAK_CLIENT_SECRET', secret)

    try:
        token = partial(get_token, os.environ['KEYCLOAK_URL'],
                client_id='testclient',
                client_secret=secret,
        )
        rest_client = RestClient(
            f'{os.environ["KEYCLOAK_URL"]}/auth/admin/realms/testrealm',
            token=token,
            retries=0,
        )

        tok = bootstrap.get_token()
        url = f'{os.environ["KEYCLOAK_URL"]}/auth/admin/realms/testrealm/clients'
        args = {
            'authorizationServicesEnabled': False,
            'clientId': 'idp_client',
            'consentRequired': False,
            'defaultClientScopes': ['web-origins', 'roles', 'profile'],
            'directAccessGrantsEnabled': True,
            'enabled': True,
            'fullScopeAllowed': True,
            'implicitFlowEnabled': False,
            'optionalClientScopes': ['offline_access', 'microprofile-jwt', 'email'],
            'serviceAccountsEnabled': False,
            'standardFlowEnabled': True,
            'rootUrl': f'http://localhost:{port}',
            'redirectUris': [f'http://localhost:{port}/*'],
            'publicClient': False,
        }
        r = requests.post(url, json=args,
                        headers={'Authorization': f'bearer {tok}'})

        url = f'{os.environ["KEYCLOAK_URL"]}/auth/admin/realms/testrealm/clients'
        r = requests.get(url, headers={'Authorization': f'bearer {tok}'})
        r.raise_for_status()
        clients = r.json()
        if not any(c['clientId'] == 'idp_client' for c in clients):
            raise Exception(f'failed to create client "idp_client"')
        kc_id = None
        for c in clients:
            if c['clientId'] == 'idp_client':
                kc_id = c['id']
                break

        url = f'{os.environ["KEYCLOAK_URL"]}/auth/admin/realms/testrealm/clients/{kc_id}/client-secret'
        r = requests.get(url, headers={'Authorization': f'bearer {tok}'})
        r.raise_for_status()
        idp_secret = r.json()['value']
        if not idp_secret:
            raise Exception('failed to get client_secret for "idp_client"')

        with env(IDP_ADDRESS=f'{os.environ["KEYCLOAK_URL"]}/auth/realms/testrealm',
                 IDP_CLIENT_ID='idp_client',
                 IDP_CLIENT_SECRET=idp_secret):
            yield rest_client
    finally:
        tok = bootstrap.get_token()
        bootstrap.delete_service_role('testclient', token=tok)
        bootstrap.delete_realm('testrealm', token=tok)


@pytest_asyncio.fixture
async def keycloak(keycloak_bootstrap, storage):
    users, _, _ = storage
    for user in users:
        await create_user(user, 'test', 'user', f'{user}@test.test', rest_client=keycloak_bootstrap)
        await set_user_password(user, 'test', rest_client=keycloak_bootstrap)
    try:
        yield
    finally:
        for user in users:
            await delete_user(user, rest_client=keycloak_bootstrap)


@pytest.fixture
def server(port, storage, keycloak, mongo_clear):
    _, _, tmp_path = storage

    @asynccontextmanager
    async def fn():
        # reset issuer address to get it to update
        with env(
            CI_TESTING=True,
            PORT=port,
            ISSUER_ADDRESS='',
            POSIX_PATH=str(tmp_path),
            DEVICE_CODE_POLLING_INTERVAL=.1):

            start_event = threading.Event()
            stop_event = threading.Event()
            async def run_async():
                s = Server()
                await s.start()
                start_event.set()
                while not stop_event.is_set():
                    await asyncio.sleep(.1)
                await s.stop()
            def run():
                asyncio.run(run_async())
            t = threading.Thread(target=run)
            t.start()
            while not start_event.is_set():
                await asyncio.sleep(.1)
            try:
                yield f'http://localhost:{port}'
            finally:
                stop_event.set()
                await asyncio.sleep(.1)
                t.join(timeout=1)
                if t.is_alive():
                    raise Exception('server thread is stuck')

    yield fn


async def test_main(server):
    async with server() as address:
        client = RestClient(address, retries=0)

        ret = await client.request('GET', '/')
        assert ret == {}


async def test_wellknown(server):
    async with server() as address:
        client = RestClient(address, retries=0)
        ret = await client.request('GET', '/.well-known/openid-configuration')
        assert ret['issuer'] == address
        assert ret['authorization_endpoint']



@pytest.mark.parametrize("key", scitoken_issuer.config.DEFAULT_KEY_ALGORITHMS)
async def test_certs(key, server):
    with env(KEY_TYPE=key):
        async with server() as address:
            client = RestClient(address, retries=0)
            ret = await client.request('GET', '/.well-known/openid-configuration')
            assert ret['jwks_uri'] == f'{address}/certs'

            ret = await client.request('GET', '/certs')
            assert len(ret['keys']) > 0


async def test_openid_auth(server):
    async with server() as address:
        auth = OpenIDAuth(address)
        assert auth.provider_info is not None


async def test_health(server):
    async with server() as address:
        client = RestClient(address, retries=0)
        ret = await client.request('GET', '/healthz')
        assert ret['posix_path']
        assert ret['jwks']


### client registration ###

@asynccontextmanager
async def register_client(server, scopes):
    rc = RestClient(server, retries=0)
    meta = {
        'grant_types': [
            'authorization_code',
            'urn:ietf:params:oauth:grant-type:device_code',
        ],
        'client_name': 'test',
        'scope': ' '.join(scopes),
    }
    ret = await rc.request('POST', '/client', meta)
    try:
        yield ret
    finally:
        path = ret['registration_client_uri'][len(server):]
        rc2 = RestClient(server, token=ret['registration_access_token'], retries=0)
        await rc2.request('DELETE', path)


async def test_registration(server):
    async with server() as address, register_client(address, scopes=['openid']) as data:
        logging.info('client data: %r', data)
        assert 'client_id' in data
        assert 'client_secret' in data
        assert 'registration_client_uri' in data
        assert 'registration_access_token' in data

        path = data['registration_client_uri'][len(address):]
        rc = RestClient(address, token=data['registration_access_token'], retries=0)
        ret = await rc.request('GET', path)
        assert data == ret

        with pytest.raises(requests.exceptions.HTTPError) as exc:
            await rc.request('PUT', path, {})
        assert 405 == exc.value.response.status_code


@asynccontextmanager
async def make_client(server, scopes=[]):
    async with register_client(server, scopes=['openid', 'storage.read', 'storage.modify']) as data:
        logging.debug('doing device grant')
        rc = DeviceGrantAuth(
            server,
            server,
            client_id=data['client_id'],
            client_secret=data['client_secret'],
            scopes=scopes,
            timeout=1,
            retries=0,
        )
        yield rc


def do_device_login(user):
    def fn(req):
        logging.warning('QR code! %r', req)
        with requests.Session() as session:
            r = session.get(req['verification_uri_complete'])
            r.raise_for_status()
            logging.info('redirections: %r', r.history)
            # should redirect to IdP login form, for us to complete
            soup = bs4.BeautifulSoup(r.text, features='html.parser', multi_valued_attributes=None)
            form = soup.select_one('#kc-form-login')
            if not form:
                raise Exception('cannot find login form in Keycloak!')
            action = unescape(form['action'])  # type:ignore
            logging.info('logging in to IdP with %s', action)
            logging.info('cookies: %r', r.cookies)
            data = {
                'username': user,
                'password': 'test',
            }
            cookies = requests.utils.dict_from_cookiejar(r.cookies)
            r2 = session.post(action, data=data, cookies=cookies)
            logging.info('cookies2: %r', r2.cookies)
            try:
                r2.raise_for_status()
            except Exception as e:
                logging.error('bad request: %s', r2.text, exc_info=True)
                raise
            logging.info('redirections: %r', r2.history)
            # should redirect back to issuer
    return fn


@pytest.mark.parametrize("key", scitoken_issuer.config.DEFAULT_KEY_ALGORITHMS)
async def test_device_auth(key, server, storage, monkeypatch):
    users, _, _ = storage
    with env(KEY_TYPE=key):
        async with server() as address:
            for user in users:
                login = Mock(side_effect=do_device_login(user))
                monkeypatch.setattr('rest_tools.client.device_client._print_qrcode', login)

                async def common(scopes):
                    login.reset_mock()
                    async with make_client(address, scopes) as rc:
                        token = rc._openid_token()
                        assert token
                        assert rc.refresh_token

                        assert login.call_count == 1

                        data = jwt.decode(token, options={"verify_signature": False})
                        assert data['sub'] == user
                        return data

                match user:
                    case 'test1':
                        data = await common(['storage.modify:/data/ana/project1/sub1'])
                        assert 'storage.modify:/data/ana/project1/sub1' in data['scope']
                        data = await common(['storage.modify:/data/ana/project3/sub1'])
                        assert 'storage.modify:/data/ana/project3/sub1' in data['scope']
                    case 'test2':
                        with pytest.raises(Exception) as e:
                            await common(['storage.modify:/data/ana/project1/sub1'])
                        cause: requests.HTTPError = e.value.__cause__  # type: ignore
                        assert 'invalid scopes' == cause.response.json()['error_description']
                        data = await common(['storage.read:/data/ana/project3/sub1'])
                        assert 'storage.read:/data/ana/project3/sub1' in data['scope']
                    case 'non':
                        with pytest.raises(Exception) as e:
                            await common(['storage.modify:/data/ana/project1/sub1'])
                        cause: requests.HTTPError = e.value.__cause__  # type: ignore
                        if not cause:
                            logging.warning('%r', e.value)
                        assert 'invalid scopes' == cause.response.json()['error_description']
                        with pytest.raises(Exception) as e:
                            await common(['storage.modify:/data/ana/project3/sub1'])
                        cause: requests.HTTPError = e.value.__cause__  # type: ignore
                        assert 'invalid scopes' == cause.response.json()['error_description']


async def test_userinfo(server, storage, monkeypatch):
    users, _, _ = storage
    async with server() as address:
        for user in users:
            login = Mock(side_effect=do_device_login(user))
            monkeypatch.setattr('rest_tools.client.device_client._print_qrcode', login)
            scopes = ['storage.read:/data/ana/project1/sub1']
            async with make_client(address, scopes) as rc:
                token = rc._openid_token()
                assert token

                ret = await rc.request('GET', '/userinfo')
                logging.info('userinfo: %r', ret)
                assert ret['sub'] == user
                # IdP params
                assert ret['name'] == 'test user'
                assert ret['email'] == f'{user}@test.test'


async def test_authorize(server, storage, monkeypatch):
    users, _, _ = storage
    async with server() as address:
        for user in users:
            login = Mock(side_effect=do_device_login(user))
            monkeypatch.setattr('rest_tools.client.device_client._print_qrcode', login)
            scope = 'storage.read:/data/ana/project1/sub1'
            async with register_client(address, scopes=['openid', 'storage.read', 'storage.modify']) as data:
                logging.info('client registration data: %r', data)
                client_id = data['client_id']
                client_secret = data['client_secret']

                with requests.Session() as session:
                    redirect_uri = 'http://localhost/foo/bar'
                    args = {
                        'client_id': client_id,
                        'response_type': 'code',
                        'redirect_uri': redirect_uri,
                        'scope': scope,
                    }
                    r = session.get(f'{address}/authorize', params=args)
                    r.raise_for_status()
                    logging.info('redirections: %r', r.history)
                    # should redirect to IdP login form, for us to complete
                    soup = bs4.BeautifulSoup(r.text, features='html.parser', multi_valued_attributes=None)
                    form = soup.select_one('#kc-form-login')
                    if not form:
                        raise Exception('cannot find login form in Keycloak!')
                    action = unescape(form['action'])  # type:ignore
                    logging.info('logging in to IdP with %s', action)
                    logging.info('cookies: %r', r.cookies)
                    data = {
                        'username': user,
                        'password': 'test',
                    }
                    cookies = requests.utils.dict_from_cookiejar(r.cookies)
                    url = None
                    try:
                        r2 = session.post(action, data=data, cookies=cookies)
                        logging.info('cookies2: %r', r2.cookies)
                        url = r2.request.url
                        r2.raise_for_status()
                    except requests.exceptions.ConnectionError as e:
                        if e.request:
                            url = e.request.url
                            if not url or not url.startswith(redirect_uri):
                                raise
                    except requests.exceptions.RequestException as e:
                        if e.response:
                            logging.error('bad request: %s', e.response.text, exc_info=True)
                        raise
                    else:
                        logging.info('redirections: %r', r2.history)
                    # should redirect back to issuer
                    p = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(str(p.query)) if p.query else ''
                    assert params
                    assert 'code' in params

                    args = {
                        'grant_type': 'authorization_code',
                        'client_id': client_id,
                        'code': params['code'][0],
                        'redirect_uri': redirect_uri,
                    }
                    r3 = session.post(f'{address}/token', data=args, auth=HTTPBasicAuth(client_id, client_secret))
                    r3.raise_for_status()
                    ret = r3.json()
                    assert 'access_token' in ret
                    assert 'refresh_token' in ret


async def test_scopes(server, storage, monkeypatch):
    users, _, _ = storage
    async with server() as address:
        for user in users:
            login = Mock(side_effect=do_device_login(user))
            monkeypatch.setattr('rest_tools.client.device_client._print_qrcode', login)
            scopes = ['storage.read:/data/ana/project1/sub1']
            async with make_client(address, scopes) as rc:
                token = rc._openid_token()
                assert token
                access_data = jwt.decode(token, options={"verify_signature": False})
                logging.info('access token: %r', access_data)
                assert all('storage' in s for s in access_data['scope'].split())
                
                refresh_data = jwt.decode(rc.refresh_token, options={"verify_signature": False})
                assert access_data['scope'] in refresh_data['scope']
                assert 'offline_access' in refresh_data['scope']


async def test_scitokens(server, storage, monkeypatch):
    """
    scitokens-cpp requires specific claim values:
    * integer times for exp, iat, nbf
    * wlcg.ver is a string "1.0"
    """
    users, _, _ = storage
    user = 'test1'

    with env(CUSTOM_CLAIMS_JSON='{"aud": ["https://wlcg.cern.ch/jwt/v1/any"], "wlcg.ver":"1.0"}'):
        async with server() as address:
            login = Mock(side_effect=do_device_login(user))
            monkeypatch.setattr('rest_tools.client.device_client._print_qrcode', login)
            scopes = ['storage.read:/data/ana/project1/sub1']
            async with make_client(address, scopes) as rc:
                token = rc._openid_token()
                assert token
                access_data = jwt.decode(token, options={"verify_signature": False})
                logging.info('access token: %r', access_data)
                assert isinstance(access_data['exp'], int)

                assert access_data['wlcg.ver'] == '1.0'

                assert 'https://wlcg.cern.ch/jwt/v1/any' in access_data['aud']
