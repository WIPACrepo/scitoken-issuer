import scitoken_issuer.config

from .util import env


def test_json():
    c = scitoken_issuer.config.ConfigJson('{"foo": "bar"}')
    assert c == {"foo": "bar"}


def test_custom_claims():
    with env(CUSTOM_CLAIMS='{"foo":"bar"}'):
        assert scitoken_issuer.config.ENV.CUSTOM_CLAIMS == {"foo": "bar"}


def test_static_clients():
    with env(STATIC_CLIENTS='{"foo":"bar"}'):
        assert scitoken_issuer.config.ENV.STATIC_CLIENTS == {"foo": "bar"}


def test_static_impersonation_clients():
    with env(STATIC_IMPERSONATION_CLIENTS='{"foo":"bar"}'):
        assert scitoken_issuer.config.ENV.STATIC_IMPERSONATION_CLIENTS == {"foo": "bar"}
