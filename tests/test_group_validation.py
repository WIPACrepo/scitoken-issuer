from unittest.mock import MagicMock
from scitoken_issuer import group_validation


def test_get_all_groups_PAM(monkeypatch):
    groups = [MagicMock()]
    m = MagicMock(return_value=groups)
    monkeypatch.setattr(group_validation, 'getgrall', m)

    PAM = group_validation.LookupPAM()

    ret = PAM.get_all_groups()
    assert len(ret) == len(groups)
    assert ret[0].gid == groups[0].gr_gid
    assert m.call_count == 1

    ret = PAM.get_all_groups()
    assert m.call_count == 1


def test_get_user_info_PAM(monkeypatch):
    user1 = MagicMock()
    m = MagicMock(return_value=user1)
    monkeypatch.setattr(group_validation, 'getpwnam', m)

    PAM = group_validation.LookupPAM()

    ret = PAM.get_user_info('user1')
    assert ret.uid == user1.pw_uid
    assert m.call_count == 1

    ret = PAM.get_user_info('user1')
    assert ret.uid == user1.pw_uid
    assert m.call_count == 1

    user2 = MagicMock()
    m.return_value = user2

    ret = PAM.get_user_info('user2')
    assert ret.uid == user2.pw_uid
    assert m.call_count == 2

def test_validator(storage):
    users, groups, tmp_path = storage
    v = group_validation.Validator(tmp_path)
    assert v(username='test1', scope='storage.read:/') == False
    assert v(username='test1', scope='storage.read:/data/user/test1') == True
    assert v(username='test1', scope='storage.modify:/data/user/test1') == True
    assert v(username='test1', scope='storage.read:/data/ana/project1') == True
    assert v(username='test1', scope='storage.modify:/data/ana/project1') == True
    assert v(username='test1', scope='storage.modify:/data/ana/project1/sub1') == True
    assert v(username='test1', scope='storage.read:/data/ana/project2') == True
    assert v(username='test1', scope='storage.modify:/data/ana/project2') == False
    assert v(username='test1', scope='storage.read:/data/ana/project2/sub1') == False
    assert v(username='test1', scope='storage.modify:/data/ana/project2/sub1') == False
    assert v(username='test1', scope='storage.read:/data/ana/project3') == True
    assert v(username='test1', scope='storage.modify:/data/ana/project3') == False
    assert v(username='test1', scope='storage.read:/data/ana/project3/sub1') == True
    assert v(username='test1', scope='storage.modify:/data/ana/project3/sub1') == True
    
    assert v(username='test2', scope='storage.read:/') == False
    assert v(username='test2', scope='storage.read:/data/user/test2') == True
    assert v(username='test2', scope='storage.modify:/data/user/test2') == True
    assert v(username='test2', scope='storage.read:/data/ana/project1') == True
    assert v(username='test2', scope='storage.modify:/data/ana/project1') == True
    assert v(username='test2', scope='storage.modify:/data/ana/project1/sub1') == False
    assert v(username='test2', scope='storage.read:/data/ana/project2') == True
    assert v(username='test2', scope='storage.modify:/data/ana/project2') == True
    assert v(username='test2', scope='storage.read:/data/ana/project2/sub1') == False
    assert v(username='test2', scope='storage.modify:/data/ana/project2/sub1') == False
    assert v(username='test2', scope='storage.read:/data/ana/project3') == True
    assert v(username='test2', scope='storage.modify:/data/ana/project3') == False
    assert v(username='test2', scope='storage.read:/data/ana/project3/sub1') == True
    assert v(username='test2', scope='storage.modify:/data/ana/project3/sub1') == False
