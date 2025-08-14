from contextlib import contextmanager
import dataclasses
import logging

from wipac_dev_tools.enviro_tools import deconstruct_typehint, _typecast_for_dataclass

from scitoken_issuer import config


@contextmanager
def env(**kwargs):
    logging.debug('changing ENV: %r', kwargs)
    old_env = config.ENV

    # retype things
    for field in dataclasses.fields(config.ENV):
        if field.name not in kwargs:
            continue
        if not field.init:
            continue
        
        env_val = kwargs[field.name]
        if isinstance(env_val, str):
            typ, arg_typs = deconstruct_typehint(field)
            
            # cast value to type
            try:
                kwargs[field.name] = _typecast_for_dataclass(
                    env_val, typ, arg_typs, None, '='
                )
            except ValueError as e:
                raise ValueError(
                    f"'{field.type}'-indicated value is not a legal value: "
                    f"var='{field.name}' value='{env_val}'"
                ) from e

    new_env = dataclasses.replace(old_env, **kwargs)
    try:
        config.ENV = new_env
        yield
    finally:
        config.ENV = old_env
