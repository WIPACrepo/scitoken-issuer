import jwt.algorithms
from scitoken_issuer import gen_keys


def test_rsa():
    keys = gen_keys.GenKeysRSA()
    keys.pem_format()

    ret = keys.gen_jwk(kid='foo')
    assert ret['kid'] == 'foo'

    key = jwt.algorithms.RSAAlgorithm.from_jwk(ret)
    assert key == keys.public_key


def test_ec():
    keys = gen_keys.GenKeysEC()
    keys.pem_format()

    ret = keys.gen_jwk(kid='foo')
    assert ret['kid'] == 'foo'

    key = jwt.algorithms.ECAlgorithm.from_jwk(ret)
    assert key == keys.public_key


def test_okp():
    keys = gen_keys.GenKeysOKP()
    keys.pem_format()

    ret = keys.gen_jwk(kid='foo')
    assert ret['kid'] == 'foo'

    key = jwt.algorithms.OKPAlgorithm.from_jwk(ret)
    assert key == keys.public_key
