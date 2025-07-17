from argparse import ArgumentParser
from collections import defaultdict
import logging
from pathlib import Path
from grp import getgrall,getgrgid


class Group:
    __slots__ = ['group', 'dirs']
    def __init__(self):
        self.group = None
        self.dirs = defaultdict(newgroup)

def newgroup():
    return Group()


class GroupTree:
    def __init__(self, base_path):
        self.base_path = Path(base_path)
        self.group_tree = defaultdict(newgroup)

        self.group_cache = {g.gr_gid: g.gr_name for g in getgrall()}
        for g in self.group_cache:
            if not self.group_cache[g]:
                logging.warning('%d = %s is None?', g, self.group_cache[g])
                raise Exception('weird group')

    def get_group_name(self, gid):
        if gid not in self.group_cache:
            g = getgrgid(gid)
            self.group_cache[gid] = g.gr_name
        return self.group_cache[gid]

    def walk(self):
        for root,dirs,_ in self.base_path.walk(follow_symlinks=True):
            logging.warning('scanning %s', root)
            for d in sorted(dirs):
                path = (root / d).resolve(strict=True)
                if path.name in ('.', '..'):
                    continue
                logging.info('processing %s', path)
                if not path.is_relative_to(self.base_path):
                    logging.warning('external symlink detected! %s -> %s', root/d, path)
                    continue
                leaf = self.group_tree
                for p in reversed(path.relative_to(self.base_path).parents):
                    p = str(p.name)
                    logging.debug('dir: %s', p)
                    if p and p != '.':
                        leaf = leaf[p].dirs
                if path.name in leaf and leaf[path.name].group:
                    logging.warning('loop detected! %s -> %s', root/d, path)
                    dirs.remove(d)
                    continue
                leaf[path.name].group = self.get_group_name(path.stat().st_gid)


    def _examine_children(self, path, tree):
        groups = set()
        for name,t in tree.items():
            groups.add(t.group)
            if t.dirs:
                child_groups = self._examine_children(path / name, t.dirs)
                if child_groups == {t.group}:
                    logging.info('%s - same group, so drop dirs', path / name)
                    t.dirs = {}
                else:
                    groups.update(child_groups)
        return groups

    def remove_dup_children(self):
        self._examine_children(self.base_path, self.group_tree)


def print_children(root, tree):
    ch = defaultdict(list)
    for name,t in tree.items():
        if not t.group:
            logging.warning("group: %r, name: %r", t.group, name)
        ch[t.group].append(name)
    for grp,names in ch.items():
        print(root, '/[', ','.join(names), '] - ', grp, sep='')
        for name in names:
            if tree[name].dirs:
                print_children(root/name, tree[name].dirs)


def main():
    parser = ArgumentParser()
    parser.add_argument('-p', '--path', default='/data')
    parser.add_argument('--log-level', default='INFO')
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())

    gt = GroupTree(args.path)
    gt.remove_dup_children()

    print_children(gt.base_path, gt.group_tree)


if __name__ == '__main__':
    main()
