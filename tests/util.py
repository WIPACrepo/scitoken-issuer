from contextlib import contextmanager
import dataclasses
import logging

from scitoken_issuer import config


@contextmanager
def env(**kwargs):
    logging.debug('changing ENV: %r', kwargs)
    old_env = config.ENV
    new_env = dataclasses.replace(old_env, **kwargs)
    try:
        config.ENV = new_env
        yield
    finally:
        config.ENV = old_env
