import logging
from os import stat as os_stat, stat_result
from pathlib import Path
import socket

import motor.motor_asyncio
import pytest
import pytest_asyncio
from unittest.mock import Mock, MagicMock, patch
from scitoken_issuer import config, group_validation


@pytest.fixture(scope="session")
def monkeysession():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.fixture(scope='session')
def port():
    """Get an ephemeral port number."""
    # https://unix.stackexchange.com/a/132524
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    addr = s.getsockname()
    ephemeral_port = addr[1]
    s.close()
    return ephemeral_port


@pytest_asyncio.fixture
async def mongo_clear():
    db_url, db_name = config.ENV.MONGODB_URL.rsplit('/', 1)
    client = motor.motor_asyncio.AsyncIOMotorClient(db_url, serverSelectionTimeoutMS=10)

    async def _clean(db_name):
        db = client[db_name]
        cols = await db.list_collection_names()
        for c in cols:
            await db[c].drop()

    await _clean(db_name)
    yield
    await _clean(db_name)


def _mkuser(uid, gid):
    ret = Mock(spec=['uid', 'gid'])
    ret.uid = uid
    ret.gid = gid
    return ret


def _mkgroup(gid, members):
    ret = Mock(spec=['gid', 'members'])
    ret.gid = gid
    ret.members = members
    return ret

def _mock_perms(uid, gid, mode):
    ret = Mock(spec=stat_result)
    ret.st_uid = uid
    ret.st_gid = gid
    ret.st_mode = mode
    return ret

@pytest.fixture
def storage(tmp_path, monkeypatch):
    groups = [
        _mkgroup(12350, ['test1', 'test2']),
        _mkgroup(12351, ['test1']),
        _mkgroup(12352, ['test2']),
        _mkgroup(12353, []),
    ]
    users = {
        'non': {'uid': 12300, 'gid': 12300},
        'test1': {'uid': 12345, 'gid': 12345},
        'test2': {'uid': 12346, 'gid': 12347},
    }
    def get_user(username):
        return _mkuser(**users[username])
    PAM = MagicMock()
    PAM.return_value.get_all_groups = MagicMock(return_value=groups)
    PAM.return_value.get_user_info = MagicMock(side_effect=get_user)
    monkeypatch.setattr(group_validation, 'LookupPAM', PAM)

    def get_stat(path, *args, **kwargs):
        if Path(path).is_relative_to(tmp_path):
            rpath = str(path)[len(str(tmp_path)):]
            logging.debug(f'mocking! "{rpath}"')
            if rpath.startswith('/data/user/'):
                user = users[rpath.split('/')[-1]]
                return _mock_perms(user['uid'], user['gid'], 0o775)
            elif rpath.startswith('/data/ana'):
                if rpath.startswith('/data/ana/project1/sub1'):
                    return _mock_perms(1, 12351, 0o775)
                elif rpath.startswith('/data/ana/project1'):
                    return _mock_perms(1, 12350, 0o775)
                elif rpath.startswith('/data/ana/project2/sub1'):
                    return _mock_perms(1, 12353, 0o770)
                elif rpath.startswith('/data/ana/project2'):
                    return _mock_perms(1, 12352, 0o775)
                elif rpath.startswith('/data/ana/project3/sub1'):
                    return _mock_perms(1, 12345, 0o775)
                elif rpath.startswith('/data/ana/project3'):
                    return _mock_perms(1, 12353, 0o775)
            return _mock_perms(1, 1, 0o700)
        else:
            return os_stat(str(path), *args, **kwargs)
    monkeypatch.setattr(group_validation, 'get_stat', get_stat)

    data_user = tmp_path / 'data' / 'user'
    data_user.mkdir(parents=True)
    for username in users:
        p = data_user / username
        p.mkdir()
        p.chmod(0o755)

    data_ana = tmp_path / 'data' / 'ana'
    data_ana.mkdir(parents=True)
    data_ana.chmod(0o755)

    p = data_ana / 'project1'
    p2 = data_ana / 'project1' / 'sub1'
    p2.mkdir(parents=True)
    p.chmod(0o775)
    p2.chmod(0o775)
    #chown(str(p2), -1, 12351)
    #chown(str(p), -1, 12350)

    p = data_ana / 'project2'
    p2 = data_ana / 'project2' / 'sub1'
    p2.mkdir(parents=True)
    p.chmod(0o775)
    p2.chmod(0o775)
    #chown(str(p2), -1, 12353)
    #chown(str(p), -1, 12352)

    p = data_ana / 'project3'
    p2 = data_ana / 'project3' / 'sub1'
    p2.mkdir(parents=True)
    p.chmod(0o775)
    p2.chmod(0o775)
    #chown(str(p2), -1, 12345)
    #chown(str(p), -1, 12353)

    yield (users, groups, tmp_path)
