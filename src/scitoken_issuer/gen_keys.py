from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import jwt.algorithms


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

    def gen_jwk(self, kid: str = 'testing') -> dict[str, Any]:
        jwk = self.algorithm.to_jwk(self.public_key, as_dict=True)
        jwk['kid'] = kid
        return jwk


class GenKeysRSA(GenKeysBase):
    algorithm = jwt.algorithms.RSAAlgorithm

    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()


class GenKeysEC(GenKeysBase):
    algorithm = jwt.algorithms.ECAlgorithm

    def __init__(self):
        self.private_key = ec.generate_private_key(curve=ec.SECP384R1())
        self.public_key = self.private_key.public_key()


class GenKeysOKP(GenKeysBase):
    algorithm = jwt.algorithms.OKPAlgorithm

    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
