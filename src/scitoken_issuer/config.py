import dataclasses as dc
import json
import logging
import secrets
from typing import Any

from wipac_dev_tools import from_environment_as_dataclass


class ConfigError(RuntimeError):
    pass


DEFAULT_KEY_ALGORITHMS = [
    'RS256',
    'RS384',
    'RS512',
    'ES256',
    'ES384',
    'ES512',
    'EdDSA',
]


@dc.dataclass(frozen=True)
class EnvConfig:
    IDP_ADDRESS: str = ''
    IDP_CLIENT_ID: str = ''
    IDP_CLIENT_SECRET: str = ''
    IDP_USERNAME_CLAIM: str = 'preferred_username'

    ISSUER_ADDRESS: str = ''
    CUSTOM_CLAIMS: dict[str, Any] | str = ''
    KEY_TYPE: str = 'RS256'

    ACCESS_TOKEN_EXPIRATION: int = 300  # seconds
    REFRESH_TOKEN_EXPIRATION: int = 86400  # seconds
    DEVICE_CODE_POLLING_INTERVAL: int = 5  # seconds
    DEVICE_CODE_EXPIRATION: int = 600  # seconds
    AUTHORIZATION_CODE_EXPIRATION: int = 600  # seconds
    CLIENT_REGISTRATION_EXPIRATION: int = 86400  # seconds

    POSIX_PATH: str = '/'
    USE_LDAP: bool = False

    MONGODB_URL: str = 'mongodb://localhost/scitokens'
    MONGODB_USER: str = ''
    MONGODB_PASSWORD: str = ''
    MONGODB_TIMEOUT: int = 10  # seconds
    MONGODB_WRITE_CONCERN: int = 1  # number of replicas that need to be up

    HOST: str = 'localhost'
    PORT: int = 8080
    DEBUG: bool = False
    COOKIE_SECRET: str = ''

    CI_TESTING: bool = False

    PROMETHEUS_PORT: int = 0
    LOG_LEVEL: str = 'INFO'

    def __post_init__(self) -> None:
        object.__setattr__(self, 'LOG_LEVEL', self.LOG_LEVEL.upper())  # b/c frozen
        if not self.ISSUER_ADDRESS:
            object.__setattr__(self, 'ISSUER_ADDRESS', f'http://{self.HOST}:{self.PORT}')
        if not self.CI_TESTING:
            if not self.IDP_ADDRESS:
                raise ConfigError('Must specify IDP_ADDRESS in production')
            if not self.IDP_CLIENT_ID:
                raise ConfigError('Must specify IDP_CLIENT_ID in production')
            if not self.IDP_CLIENT_SECRET:
                raise ConfigError('Must specify IDP_CLIENT_SECRET in production')
            if not self.MONGODB_URL:
                raise ConfigError('Must specify MONGODB_URL in production')
        if self.CUSTOM_CLAIMS and isinstance(self.CUSTOM_CLAIMS, str):
            object.__setattr__(self, 'CUSTOM_CLAIMS', json.loads(self.CUSTOM_CLAIMS))
        if self.KEY_TYPE not in DEFAULT_KEY_ALGORITHMS:
            raise ConfigError(f'KEY_TYPE must be one of {DEFAULT_KEY_ALGORITHMS}')
        if self.MONGODB_WRITE_CONCERN < 1:
            raise ConfigError('MONGODB_WRITE_CONCERN must be greater than 0')
        if not self.COOKIE_SECRET:
            object.__setattr__(self, 'COOKIE_SECRET', secrets.token_hex(32))


ENV = from_environment_as_dataclass(EnvConfig, collection_sep=',')


def config_logging():
    # handle logging
    setlevel = {
        'CRITICAL': logging.CRITICAL,  # execution cannot continue
        'FATAL': logging.CRITICAL,
        'ERROR': logging.ERROR,  # something is wrong, but try to continue
        'WARNING': logging.WARNING,  # non-ideal behavior, important event
        'WARN': logging.WARNING,
        'INFO': logging.INFO,  # initial debug information
        'DEBUG': logging.DEBUG  # the things no one wants to see
    }

    if ENV.LOG_LEVEL not in setlevel:
        raise Exception('LOG_LEVEL is not a proper log level')
    logformat = '%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)s - %(message)s'
    logging.basicConfig(format=logformat, level=setlevel[ENV.LOG_LEVEL])
