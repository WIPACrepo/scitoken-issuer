import asyncio
import logging
import time
import uuid

import pytest
from rest_tools.utils.auth import Auth

from scitoken_issuer import config, gen_keys, state

from .util import env


def test_make_key():
    with env(KEY_TYPE='RS256'):
        key = state._make_new_key()
        assert isinstance(key, gen_keys.GenKeysRSA)

    with env(KEY_TYPE='ES256'):
        key = state._make_new_key()
        assert isinstance(key, gen_keys.GenKeysEC)

    with env(KEY_TYPE='EdDSA'):
        key = state._make_new_key()
        assert isinstance(key, gen_keys.GenKeysOKP)

    with pytest.raises(Exception):
        with env(KEY_TYPE='other'):
            key = state._make_new_key()


async def test_start(mongo_clear):
    s = state.State()
    await s.start()


async def test_start_static_clients(mongo_clear):
    with env(STATIC_CLIENTS='[{"client_id":"foo","client_secret":"bar"}]'):
        s = state.State()
        await s.start()

        ret = await s.get_client("foo")
        assert ret.static_client == True


async def test_start_static_impersonation_clients(mongo_clear):
    with env(STATIC_CLIENTS='[{"client_id":"bar","client_secret":"bar","impersonation":true}]'):
        s = state.State()
        await s.start()

        ret = await s.get_client("bar")
        assert ret.static_client == True
        assert ret.impersonation == True

    with env(STATIC_CLIENTS='[{"client_id":"foo","client_secret":"bar"},{"client_id":"bar","client_secret":"bar","impersonation":true}]'):
        s = state.State()
        await s.start()

        ret = await s.get_client("foo")
        assert ret.static_client == True
        assert ret.impersonation == False

        ret = await s.get_client("bar")
        assert ret.static_client == True
        assert ret.impersonation == True


async def test_get_jwks(mongo_clear):
    s = state.State()
    await s.start()

    ret = await s.get_jwks()
    assert ret == {'keys': []}

    await s.rotate_jwk()
    ret = await s.get_jwks()
    assert len(ret['keys']) == 1

    await s.rotate_jwk()
    ret = await s.get_jwks()
    assert len(ret['keys']) == 2

@pytest.mark.parametrize("key", config.DEFAULT_KEY_ALGORITHMS)
async def test_get_current_key(key, mongo_clear):
    with env(KEY_TYPE=key):
        s = state.State()
        await s.start()

        ret = await s.get_jwks()
        assert ret == {'keys': []}

        # first invocation should generate a new key
        k = await s.get_current_key()
        assert isinstance(k['private_key'], bytes)

        ret = await s.get_jwks()
        assert len(ret['keys']) == 1

        # check that we still get the same key
        k2 = await s.get_current_key()
        assert k == k2
        ret = await s.get_jwks()
        assert len(ret['keys']) == 1

        # now rotate keys, and see if we get the new key
        k3 = await s.rotate_jwk()
        assert k != k3
        k4 = await s.get_current_key()
        assert k3 == k4
        ret = await s.get_jwks()
        assert len(ret['keys']) == 2


async def test_get_current_key_mixed(mongo_clear):
    with env(KEY_TYPE='RS256'):
        s = state.State()
        await s.start()
        k1 = await s.get_current_key()

    with env(KEY_TYPE='RS256'):
        s = state.State()
        await s.start()
        k2 = await s.get_current_key()
        assert k1 == k2

    with env(KEY_TYPE='RS512'):
        s = state.State()
        await s.start()
        k3 = await s.get_current_key()
        assert k1 != k3

    with env(KEY_TYPE='ES256'):
        s = state.State()
        await s.start()
        k4 = await s.get_current_key()
        
    with env(KEY_TYPE='ES384'):
        s = state.State()
        await s.start()
        k5 = await s.get_current_key()
        assert k4 != k5
        
    with env(KEY_TYPE='ES521'):
        s = state.State()
        await s.start()
        k6 = await s.get_current_key()
        assert k4 != k6
        assert k5 != k6


async def test_client(mongo_clear):
    s = state.State()
    await s.start()

    await s.add_client(state.Client(
        client_id='foo',
        client_secret='bar'
    ))

    ret = await s.get_client('foo')
    assert ret.client_id == 'foo'
    assert ret.client_secret == 'bar'

    await s.update_client('foo', state.Client(client_id='foo', client_secret='bar'))
    ret = await s.get_client('foo')
    assert ret.client_id == 'foo'
    assert ret.client_secret == 'bar'

    await s.delete_client('foo')

    with pytest.raises(KeyError):
        await s.get_client('foo')

    await s.delete_client('foo')


async def test_auth_code(mongo_clear):
    s = state.State()
    await s.start()

    await s.add_auth_code(code='foo', client_id='baz', scope='foo bar')

    ret = await s.get_auth_code('foo')
    assert ret['code'] == 'foo'
    assert ret['client_id'] == 'baz'
    assert ret['scope'] == 'foo bar'

    await s.delete_auth_code('foo')

    with pytest.raises(KeyError):
        await s.get_auth_code('foo')

    await s.delete_auth_code('foo')


async def test_device_code(mongo_clear):
    s = state.State()
    await s.start()

    await s.add_device_code(device_code='foo', user_code='bar', client_id='baz')

    ret = await s.get_device_code('foo')
    assert ret['device_code'] == 'foo'
    assert ret['user_code'] == 'bar'
    assert ret['client_id'] == 'baz'
    assert ret['status'] == 'new'

    await s.update_device_code('foo', 'verified')

    ret = await s.get_device_code_by_user('bar')
    assert ret['device_code'] == 'foo'
    assert ret['user_code'] == 'bar'
    assert ret['status'] == 'verified'

    await s.delete_device_code('foo')

    with pytest.raises(KeyError):
        await s.get_device_code('foo')

    await s.delete_device_code('foo')


async def test_device_code_exp(mongo_clear):
    with env(DEVICE_CODE_EXPIRATION=1):
        s = state.State()
        await s.start()
        
        await s.add_device_code(device_code='foo', user_code='bar', client_id='baz')
        ret = await s.get_device_code('foo')
        assert ret['device_code'] == 'foo'

        await asyncio.sleep(1)

        with pytest.raises(KeyError):
            await s.get_device_code('foo')


async def test_identity(mongo_clear):
    s = state.State()
    await s.start()

    await s.put_identity_for_sub('test', 'token')

    ret = await s.get_identity_for_sub('test')
    assert ret == 'token'

    await s.put_identity_for_sub('test', 'token2')
    ret = await s.get_identity_for_sub('test')
    assert ret == 'token2'

    await s.delete_identity('test')
    with pytest.raises(KeyError):
        await s.get_identity_for_sub('test')


async def test_create_tokens_time(mongo_clear):
    with env(KEY_TYPE='RS256'):
        s = state.State()
        await s.start()
        current_key = state.get_private_key(await s.get_current_key())

        start_time = time.time()

        logging.info('key: %r', current_key)

        auth = Auth(
            secret=current_key,
            issuer=config.ENV.ISSUER_ADDRESS,
            algorithm=config.ENV.KEY_TYPE,
            integer_times=True,  # scitokens-cpp can't handle floats
        )

        username = 'test'
        access_scope = 'storage.read:/'
        access_claims = {
            'jti': uuid.uuid4().hex,
            config.ENV.IDP_USERNAME_CLAIM: username,
            'scope': access_scope,
        }
        client_id = 'client'
        scope = 'offline'
        kid = uuid.uuid4().hex
        logging.info('creating access token')
        access_token = auth.create_token(
            subject=username,
            expiration=config.ENV.ACCESS_TOKEN_EXPIRATION,
            payload=access_claims,
            headers={'kid': kid},
        )
        logging.info('creating refresh token')
        refresh_token = auth.create_token(
            subject=username,
            expiration=config.ENV.REFRESH_TOKEN_EXPIRATION,
            payload={
                'jti': uuid.uuid4().hex,
                'aud': config.ENV.ISSUER_ADDRESS,
                'azp': client_id,
                config.ENV.IDP_USERNAME_CLAIM: username,
                'idp_username': username,
                'scope': scope,
            },
            headers={'kid': kid},
        )
        logging.info('done')

        assert time.time() - start_time < .1
