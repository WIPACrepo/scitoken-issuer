from typing import Any

import jwt.algorithms
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


class GenKeysBase:
    private_key: Any
    public_key: Any
    algorithm: Any

    def pem_format(self) -> tuple[bytes, bytes]:
        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return (priv_pem, pub_pem)

    @staticmethod
    def load_private_key_from_pem(pem) -> Any:
        return serialization.load_pem_private_key(pem, password=None)

    def gen_jwk(self, kid: str = 'testing') -> dict[str, Any]:
        jwk = self.algorithm.to_jwk(self.public_key, as_dict=True)
        jwk['kid'] = kid
        return jwk


class GenKeysRSA(GenKeysBase):
    algorithm = jwt.algorithms.RSAAlgorithm

    def __init__(self, key_bytes: int = 512):
        if key_bytes not in (256, 384, 512):
            raise RuntimeError('key_bytes is not 256, 384 or 512')
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bytes*8)
        self.public_key = self.private_key.public_key()


class GenKeysEC(GenKeysBase):
    algorithm = jwt.algorithms.ECAlgorithm

    def __init__(self, curve: int = 521):
        if curve == 512:  # backwards compatibility
            curve = 521
        if curve not in (256, 384, 521):
            raise RuntimeError('curve is not 256, 384 or 521')
        self.private_key = ec.generate_private_key(curve=getattr(ec, f'SECP{curve}R1')())
        self.public_key = self.private_key.public_key()


class GenKeysOKP(GenKeysBase):
    algorithm = jwt.algorithms.OKPAlgorithm

    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
