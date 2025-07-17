# type: ignore
import logging

import scitokens
from tornado.web import HTTPError


class Error(HTTPError):
    def __init__(self, reason):
        super().__init__(400, reason=reason)


class Validator:
    """
    A validator for scitokens, which validates the token claims and enforces
    policy for the current request based on the scopes.

    Args:
        issuers (list): valid issuers
        audience (str): token audience
        base_path (str): server base path
    """
    def __init__(self, issuers, audience, base_path):
        self.issuers = issuers
        self.audience = audience
        self.base_path = base_path

        self.enforcers = {issuer: scitokens.Enforcer(issuer, audience) for issuer in issuers}

    def __call__(self, raw_token, method, path):
        """
        Validate a token.

        Args:
            raw_token (str): the raw token from the Authorization header
            method (str): the method to validate
            path (str): the path to validate

        Returns:
            token (dict): extracted token information

        Raises:
            Error
        """
        op = 'read' if method == 'GET' else 'write'

        try:
            token = scitokens.SciToken.deserialize(raw_token, audience=self.audience)
        except Exception:
            logging.info('failed to deserialize token', exc_info=True)
            raise Error('invalid token')

        if token['iss'] not in self.enforcers:
            logging.info(f'invalid token issuer: {token["iss"]}')
            raise Error('invalid token issuer')
        enforcer = self.enforcers[token['iss']]

        # path should be base_path / auth_path / request_path
        if not path.startswith(self.base_path):
            logging.info(f'invalid base path: {path}')
            raise Error('invalid base path')
        auth_request_path = path[len(self.base_path):]
        if not auth_request_path.startswith('/'):
            auth_request_path = f'/{auth_request_path}'

        try:
            if enforcer.test(token, op, auth_request_path):
                return token
        except Exception:
            logging.info('failed enforcer', exc_info=True)
            raise Error('invalid authorization')
        else:
            logging.info(f'failed validation: {enforcer.last_failure}')
            raise Error('invalid authorization')
