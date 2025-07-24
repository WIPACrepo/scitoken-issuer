import pytest
from scitoken_issuer import state, gen_keys, config

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


async def test_client(mongo_clear):
    s = state.State()
    await s.start()

    await s.add_client({
        'client_id': 'foo',
        'bar': 'baz',
    })

    ret = await s.get_client('foo')
    assert ret['client_id'] == 'foo'
    assert ret['bar'] == 'baz'

    await s.update_client('foo', {'blah': 'foo'})
    ret = await s.get_client('foo')
    assert ret['client_id'] == 'foo'
    assert ret['blah'] == 'foo'

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
