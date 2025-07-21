import scitoken_issuer.config

from .util import env

def test_custom_claims():
    with env(CUSTOM_CLAIMS_JSON='{"foo":"bar"}'):
        assert scitoken_issuer.config.ENV.CUSTOM_CLAIMS == {"foo": "bar"}
