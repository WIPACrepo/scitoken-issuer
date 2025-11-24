from collections import namedtuple
from grp import getgrall
import logging
from pathlib import Path
from pwd import getpwnam
import os
import stat

from cachetools import cachedmethod, TTLCache
import cachetools.func
from krs.ldap import LDAP, get_ldap_members


GroupInfo = namedtuple("GroupInfo", ["gid", "members"])


UserInfo = namedtuple("UserInfo", ["uid", "gid"])


class LookupBase:
    def __init__(self):
        self.group_cache = TTLCache(maxsize=10000, ttl=60)
        self.user_cache = TTLCache(maxsize=10000, ttl=60)


class LookupPAM(LookupBase):
    @cachedmethod(lambda self: self.group_cache)
    def get_all_groups(self) -> list[GroupInfo]:
        return [GroupInfo(g.gr_gid, g.gr_mem) for g in getgrall()]

    @cachedmethod(lambda self: self.user_cache)
    def get_user_info(self, username) -> UserInfo:
        data = getpwnam(username)
        return UserInfo(data.pw_uid, data.pw_gid)


class LookupLDAP(LookupBase):
    @cachedmethod(lambda self: self.group_cache)
    def get_all_groups(self) -> list[GroupInfo]:
        conn = LDAP()
        ret = []
        for group in conn.list_groups().values():
            ret.append(GroupInfo(group['gidNumber'], get_ldap_members(group)))
        return ret

    @cachedmethod(lambda self: self.user_cache)
    def get_user_info(self, username) -> UserInfo:
        conn = LDAP()
        data = conn.get_user(username)
        uid = data['uidNumber'] if 'uidNumber' in data else -1
        gid = data['gidNumber'] if 'gidNumber' in data else -1
        return UserInfo(uid, gid)


@cachetools.func.ttl_cache(maxsize=100000, ttl=60)
def get_stat(path: Path) -> os.stat_result:
    return os.stat(str(path))


class Validator:
    def __init__(self, base_path: str, use_ldap=False):
        self.base_path = Path(base_path if base_path else '/')
        self.lookups = LookupLDAP() if use_ldap else LookupPAM()

    def __call__(self, username='', scope='') -> bool:
        if username and scope and scope.startswith('storage.') and ':' in scope:
            perm, scope_path = scope.split('.', 1)[-1].split(':', 1)
            path = (self.base_path / scope_path.lstrip('/')).resolve()
            if not path.is_relative_to(self.base_path):
                logging.debug('path is not relative to base: %s', scope_path)
                return False
            while not path.exists():
                path = path.parent
            logging.debug('checking perms for user %s, perm %s, on path %s', username, perm, path)

            if perm in ('read', 'stage', 'create', 'modify'):
                groups = self.get_user_groups(username)
                logging.debug('groups: %r', groups)
                path_stat = get_stat(path)
                logging.debug('stat: uid:%d gid:%d', path_stat.st_uid, path_stat.st_gid)
                if path_stat.st_uid == self.lookups.get_user_info(username).uid:
                    logging.debug('match username')
                    if perm in ('read', 'stage'):
                        return bool(path_stat.st_mode & stat.S_IRUSR)
                    elif perm in ('create', 'modify'):
                        return bool(path_stat.st_mode & stat.S_IWUSR)
                elif path_stat.st_gid in groups:
                    logging.debug('match groups')
                    if perm in ('read', 'stage'):
                        return bool(path_stat.st_mode & stat.S_IRGRP)
                    elif perm in ('create', 'modify'):
                        return bool(path_stat.st_mode & stat.S_IWGRP)
                elif perm in ('read', 'stage'):
                    return bool(path_stat.st_mode & stat.S_IROTH)
                elif perm in ('create', 'modify'):
                    return bool(path_stat.st_mode & stat.S_IWOTH)

        return False

    def get_user_groups(self, username: str) -> list[int]:
        """Gets all group ids for a given username."""
        groups = [g.gid for g in self.lookups.get_all_groups() if username in g.members]
        # Add the user's primary group
        try:
            groups.append(self.lookups.get_user_info(username).gid)
        except KeyError:
            logging.info('User %s not found', username)
        return groups
