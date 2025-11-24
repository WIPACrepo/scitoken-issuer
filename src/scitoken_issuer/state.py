from dataclasses import dataclass, asdict as dc_asdict, field as dc_field
import logging
import time
from typing import Any, TypedDict
from urllib.parse import quote_plus
import uuid

import motor.motor_asyncio
import pymongo

from . import config
from .gen_keys import GenKeysBase, GenKeysEC, GenKeysOKP, GenKeysRSA


logger = logging.getLogger('state')


def _make_new_key() -> GenKeysBase:
    logger.debug('making new key of type %s', config.ENV.KEY_TYPE)
    if config.ENV.KEY_TYPE.startswith('RS'):
        return GenKeysRSA()
    elif config.ENV.KEY_TYPE.startswith('ES'):
        return GenKeysEC()
    elif config.ENV.KEY_TYPE.startswith('EdDSA'):
        return GenKeysOKP()
    raise RuntimeError('Unknown KEY_TYPE')


def _kid_gen() -> str:
    return str(uuid.uuid4())


class Key(TypedDict):
    kid: str
    time: float
    jwk: dict[str, Any]
    private_key: bytes


def check_key_type(key) -> bool:
    """
    Check if the existing key type matches the config key type.
    """
    logger.info('check_key_type: %s vs %s', config.ENV.KEY_TYPE, key['jwk']['kty'])
    if config.ENV.KEY_TYPE.startswith('RS'):
        return key['jwk']['kty'] == 'RSA'
    elif config.ENV.KEY_TYPE.startswith('ES'):
        return key['jwk']['kty'] == 'EC'
    elif config.ENV.KEY_TYPE.startswith('EdDSA'):
        return key['jwk']['kty'] == 'OKP'
    raise RuntimeError('Unknown KEY_TYPE')


@dataclass
class Client(config.Client):
    redirect_uris: list[str] = dc_field(default_factory=list)
    grant_types: list[str] = dc_field(default_factory=list)
    response_types: str = 'code'
    client_name: str = ''
    client_id_issued_at: int = -1
    client_secret_expires_at: int = -1
    static_client: bool = False
    registration_client_uri: str = ''
    registration_access_token: str = ''
    scope: str = 'storage.read storage.create storage.modify'


class State:
    """
    Hold any state for the issuer.
    """
    INDEXES = {
        'keys': {
            'kid_index': {'keys': 'kid', 'unique': True},
            'time_index': {'keys': 'time', 'unique': True},
        },
        'clients': {
            'client_index': {'keys': 'client_id', 'unique': True},
        },
        'auth_codes': {
            'code_index': {'keys': 'code', 'unique': True},
        },
        'device_codes': {
            'device_code_index': {'keys': 'device_code', 'unique': True},
            'user_code_index': {'keys': 'user_code', 'unique': True},
        },
        'identity': {
            'sub_index': {'keys': 'sub', 'unique': True},
        },
    }

    def __init__(self):
        db_url, db_name = config.ENV.MONGODB_URL.rsplit('/', 1)
        if '://' in db_url:
            proto, db_url = db_url.split('://', 1)
        else:
            proto = 'mongodb'
        if config.ENV.MONGODB_USER:
            db_user = quote_plus(config.ENV.MONGODB_USER)
            db_pass = quote_plus(config.ENV.MONGODB_PASSWORD)
            uri = f'{proto}://{db_user}:{db_pass}@{db_url}/{db_name}'
        else:
            uri = f'{proto}://{db_url}/{db_name}'
        self.mongo = motor.motor_asyncio.AsyncIOMotorClient(
            uri,
            timeoutMS=config.ENV.MONGODB_TIMEOUT*1000,
            w=config.ENV.MONGODB_WRITE_CONCERN,
        )
        self.db = self.mongo[db_name]

    async def start(self):
        for collection in self.INDEXES:
            logger.info('DB: get existing indexes')
            existing = await self.db[collection].index_information()
            for name in self.INDEXES[collection]:
                if name not in existing:
                    kwargs = self.INDEXES[collection][name]
                    logger.info('DB: creating index %s:%s %r', collection, name, kwargs)
                    await self.db[collection].create_index(name=name, **kwargs)
        logger.info('all indexes created')

        static_clients = config.ENV.STATIC_CLIENTS if config.ENV.STATIC_CLIENTS else []
        ret = await self.list_clients()
        existing_client_ids = set()
        for client in ret:
            if client.static_client and client.client_id not in static_clients:
                logger.info('deleting old static client %s', client.client_id)
                await self.delete_client(client.client_id)
            else:
                existing_client_ids.add(client.client_id)
        now = int(time.time())
        for client in static_clients:
            logger.info('setting up client %s', client.client_id)
            data = Client(
                static_client=True,
                redirect_uris=['*'],  # any uri is valid
                grant_types=['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
                client_id_issued_at=now,
                client_secret_expires_at=now + 1000000000000,  # does not expire
                **dc_asdict(client)
            )
            if client.client_id in existing_client_ids:
                await self.update_client(client.client_id, data)
            else:
                await self.add_client(data)

    async def get_jwks(self) -> dict[str, list[Any]]:
        """Get a full jwks json for all valid keys"""
        jwks = []
        async for row in self.db.keys.find({}, sort=[('time', pymongo.DESCENDING)]):
            jwks.append(row['jwk'])
        return {'keys': jwks}

    async def get_all_keys(self) -> list[Key]:
        """Get all valid keys"""
        keys = []
        async for row in self.db.keys.find({}, sort=[('time', pymongo.DESCENDING)]):
            del row['_id']
            keys.append(row)
        return keys

    async def get_current_key(self) -> Key:
        async for row in self.db.keys.find({}, sort=[('time', pymongo.DESCENDING)], limit=1):
            del row['_id']
            if not check_key_type(row):
                return await self.rotate_jwk()
            return row
        return await self.rotate_jwk()

    async def rotate_jwk(self) -> Key:
        """
        Rotate keys and make a new one.

        Keep old keys as valid, just don't sign with them.
        """
        logger.info('rotating jwk')
        new_key = _make_new_key()
        kid = _kid_gen()
        jwk = new_key.gen_jwk(kid=kid)
        private_key = new_key.pem_format()[0]
        data: Key = {
            'kid': kid,
            'time': time.time(),
            'jwk': jwk,
            'private_key': private_key,
        }
        await self.db.keys.insert_one(data.copy())
        return data

    async def invalidate_all_jwks(self):
        """
        Invalidate all existing jwks, then make a new one.
        """
        await self.db.keys.delete_many({})
        await self.rotate_jwk()

    async def add_client(self, details: Client):
        """
        Add a client.

        Raises:
            pymongo.errors.DuplicateKeyError: when the client already exists
        """
        await self.db.clients.insert_one(dc_asdict(details))

    async def list_clients(self) -> list[Client]:
        """
        List all clients.
        """
        ret = []
        async for row in self.db.clients.find({}, projection={'_id': False}):
            ret.append(Client(**row))
        return ret

    async def get_client(self, client_id: str) -> Client:
        """
        Get client details.

        Raises:
            KeyError: If the client is not found.
        """
        ret = await self.db.clients.find_one({'client_id': client_id}, projection={'_id': False})
        if ret is None:
            raise KeyError('client_id not found')
        return Client(**ret)

    async def update_client(self, client_id: str, data: Client):
        """
        Update client details.

        Raises:
            KeyError: If the client is not found.
        """
        ret = await self.db.clients.find_one_and_update({'client_id': client_id}, {'$set':  dc_asdict(data)})
        if ret is None:
            raise KeyError('client_id not found')

    async def delete_client(self, client_id: str):
        """
        Delete a client.

        Raises:
            Exception: If the client cannot be deleted.
        """
        ret = await self.db.clients.delete_one({'client_id': client_id})
        if ret.deleted_count < 1:
            # test for race
            try:
                await self.get_client(client_id)
            except KeyError:
                return
            raise Exception('client_id cannot be deleted')
        else:
            await self.db.device_codes.delete_many({'client_id': client_id})

    async def add_auth_code(self, code: str, client_id: str, scope: str = '', username: str = '', redirect=''):
        """
        Add an authorization code.
        """
        await self.db.auth_codes.insert_one({
            'code': code,
            'client_id': client_id,
            'scope': scope,
            'username': username,
            'redirect': redirect,
            'expiration': time.time() + config.ENV.DEVICE_CODE_EXPIRATION,
        })

    async def get_auth_code(self, code: str) -> dict:
        """
        Get an authorization code.

        Raises:
            KeyError: If the code is not found.
        """
        ret = await self.db.auth_codes.find_one({'code': code}, projection={'_id': False})
        if ret is None:
            raise KeyError('code not found')
        return ret

    async def delete_auth_code(self, code: str):
        """
        Delete an authorization code.

        Raises:
            Exception: If the code cannot be deleted.
        """
        ret = await self.db.auth_codes.delete_one({'code': code})
        if ret.deleted_count < 1:
            # test for race
            try:
                await self.get_auth_code(code)
            except KeyError:
                return
            raise Exception('code cannot be deleted')

    async def add_device_code(self, device_code: str, user_code: str, client_id: str, scope: str = ''):
        """
        Add a device code.

        Valid device code statuses:
        * new - a new request
        * verified - a request was verified by a user
        * denied - a request was denied by a user
        * (deleted) - a request is complete/expired
        """
        await self.db.device_codes.insert_one({
            'device_code': device_code,
            'user_code': user_code,
            'client_id': client_id,
            'scope': scope,
            'expiration': time.time() + config.ENV.DEVICE_CODE_EXPIRATION,
            'status': 'new',
            'username': None,
        })

    async def update_device_code(self, device_code: str, status: str, username: str | None = None):
        """
        Update a device code status.
        """
        data = {'status': status}
        if username:
            data['username'] = username
        ret = await self.db.device_codes.find_one_and_update(
            {'device_code': device_code},
            {'$set': data},
        )
        if ret is None:
            raise KeyError('device_code not found')

    async def get_device_code(self, device_code: str) -> dict:
        """
        Get a device code.

        Raises:
            KeyError: If the device code is not found.
        """
        ret = await self.db.device_codes.find_one({'device_code': device_code}, projection={'_id': False})
        if ret is None:
            raise KeyError('device_code not found')
        return ret

    async def get_device_code_by_user(self, user_code: str) -> dict:
        """
        Get a device code by user_code.

        Raises:
            KeyError: If the device code is not found.
        """
        ret = await self.db.device_codes.find_one({'user_code': user_code}, projection={'_id': False})
        if ret is None:
            raise KeyError('device_code not found')
        return ret

    async def delete_device_code(self, device_code: str):
        """
        Delete a device code.

        Raises:
            Exception: If the device code cannot be deleted.
        """
        ret = await self.db.device_codes.delete_one({'device_code': device_code})
        if ret.deleted_count < 1:
            # test for race
            try:
                await self.get_device_code(device_code)
            except KeyError:
                return
            raise Exception('device_code cannot be deleted')

    async def put_identity_for_sub(self, sub: str, token: str):
        """Put identity refresh token for a subject"""
        await self.db.identity.replace_one({'sub': sub}, {
            'sub': sub,
            'token': token,
        }, upsert=True)

    async def get_identity_for_sub(self, sub: str) -> str:
        """
        Get identity refresh token for a subject.

        Raises:
            KeyError: If the subject is not found.
        """
        ret = await self.db.identity.find_one({'sub': sub})
        if ret is None:
            raise KeyError('identity not found')
        return ret['token']

    async def delete_identity(self, sub: str):
        """
        Delete identity for subject.
        """
        ret = await self.db.identity.delete_one({'sub': sub})
        if ret.deleted_count < 1:
            # test for race
            try:
                await self.get_identity_for_sub(sub)
            except KeyError:
                return
            raise Exception('identity cannot be deleted')
