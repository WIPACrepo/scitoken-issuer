import logging

import scitokens
from tornado.web import HTTPError

class Error(HTTPError):
    def __init__(self, reason):
        super().__init__(400, reason=reason)


class SciTokenIssuer:
    """
    An issuer for scitokens.

    Args:
        issuer (str): name of the issuer, to embed in tokens
        audience (str): default token audience
    """
    def __init__(self, issuer, audience=None):
        self.issuer = issuer
        self.audience = audience

    def create_token(self, user, audience=None):
        """
        Create a scitoken.

        Args:
            user (str): username
            audience (str): token audience
        """
        if not audience:
            audience = self.audience if self.audience else 'ANY'


        # set uid gid claims

