import scitoken_issuer.config

from .util import env


def test_json():
    c = scitoken_issuer.config.ConfigJson('{"foo": "bar"}')
    assert c == {"foo": "bar"}


def test_custom_claims():
    with env(CUSTOM_CLAIMS='{"foo":"bar"}'):
        assert scitoken_issuer.config.ENV.CUSTOM_CLAIMS == {"foo": "bar"}


def test_static_clients():
    c = [scitoken_issuer.config.Client('foo', 'bar')]
    with env(STATIC_CLIENTS='[{"client_id":"foo","client_secret":"bar"}]'):
        assert scitoken_issuer.config.ENV.STATIC_CLIENTS == c


def test_static_impersonation_clients():
    c = [scitoken_issuer.config.Client('foo', 'bar', impersonation=True)]
    with env(STATIC_CLIENTS='[{"client_id":"foo","client_secret":"bar","impersonation":true}]'):
        assert scitoken_issuer.config.ENV.STATIC_CLIENTS == c
