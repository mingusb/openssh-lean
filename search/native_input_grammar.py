"""Pinned getopt inventory and conservative, local-only native probe atoms.

The inventory is extracted from the archived original C bytes. The policy below
selects a deliberately small subset whose arguments contain no endpoint or
shell command. Inventory coverage and policy coverage are reported separately.
"""
import ast
from dataclasses import dataclass
import hashlib
import re

from common import need


MAIN_SOURCE = {name: name + '.c' for name in (
    'scp', 'sftp', 'sftp-server', 'ssh', 'ssh-add', 'ssh-agent',
    'ssh-keygen', 'ssh-keyscan', 'ssh-keysign', 'ssh-pkcs11-helper',
    'ssh-sk-helper', 'sshd', 'sshd-auth', 'sshd-session')}

# These are parser-recognized switches that do not themselves name a remote
# endpoint, request a listener, daemonize, or change external persistent state.
# All inputs have no positional operands and run inside a private filesystem.
SAFE_FLAGS = {
    'scp': '1246ABCOpqrv',
    'sftp': '1246AahNpqrvC',
    'sftp-server': 'ehR',
    'ssh': '1246ACGKNTVXYZaknqstvxy',
    'ssh-add': 'lL',
    'ssh-agent': 'V',
    'ssh-keygen': 'BlQy',
    'ssh-keyscan': 'cDHqv46',
    'ssh-keysign': '',
    'ssh-pkcs11-helper': 'v',
    'ssh-sk-helper': 'v',
    'sshd': 'TtV',
    'sshd-auth': 'TtV',
    'sshd-session': 'TtV',
}

# Each tuple is (option, kind, literal values, terminating-mode prefix). Values
# are policy-authored local literals, never copied from untrusted program output.
# Missing paths are relative to the disposable cwd; no input file is prepared.
SAFE_ARGUMENTS = {
    'scp': (('F', 'path', ('./missing_config',), ()),
            ('P', 'number', ('0', '1'), ()),
            ('o', 'config', ('BatchMode=yes',), ())),
    'sftp': (('F', 'path', ('./missing_config',), ()),
             ('P', 'number', ('0', '1'), ()),
             ('o', 'config', ('BatchMode=yes',), ())),
    'sftp-server': (('Q', 'query', ('requests', 'unknown'), ()),),
    'ssh': (('F', 'path', ('./missing_config',), ()),
            ('p', 'number', ('0', '1'), ()),
            ('o', 'config', ('BatchMode=yes',), ())),
    'ssh-add': (),
    'ssh-agent': (),
    'ssh-keygen': (('f', 'path', ('./missing_key',), ('-l',)),),
    'ssh-keyscan': (('p', 'number', ('0', '1'), ()),
                    ('T', 'number', ('1',), ())),
    'ssh-keysign': (),
    'ssh-pkcs11-helper': (),
    'ssh-sk-helper': (),
    'sshd': (('f', 'path', ('./missing_config',), ('-T',)),
             ('p', 'number', ('0', '1'), ('-T',))),
    'sshd-auth': (('f', 'path', ('./missing_config',), ('-T',)),),
    'sshd-session': (('f', 'path', ('./missing_config',), ('-T',)),),
}

# These programs would otherwise enter daemon mode or create a key by default.
SAFE_NO_ARGUMENTS = frozenset((
    'scp', 'sftp', 'sftp-server', 'ssh', 'ssh-add', 'ssh-keyscan',
    'ssh-keysign', 'ssh-pkcs11-helper', 'ssh-sk-helper'))

STRING = re.compile(r'"(?:\\.|[^"\\])*"')
GETOPT = re.compile(
    r'\bgetopt\s*\(\s*[^,()]+\s*,\s*[^,()]+\s*,\s*'
    r'((?:"(?:\\.|[^"\\])*"\s*)+)\)', re.S)


@dataclass(frozen=True)
class Grammar:
    target: str
    source: str
    source_sha256: str
    source_line: int | None
    option_spec: str
    flags: tuple[str, ...]
    arguments: tuple[str, ...]
    ambiguous: tuple[str, ...]


def parse_spec(spec):
    flags, arguments = [], []
    arities = {}
    ambiguous = set()
    index = 0
    while index < len(spec):
        option = spec[index]
        need(option.isascii() and option.isalnum(),
             'Unsupported getopt option in archived C source')
        takes_value = index + 1 < len(spec) and spec[index + 1] == ':'
        if option in arities:
            if arities[option] != takes_value:
                ambiguous.add(option)
        else:
            arities[option] = takes_value
            (arguments if takes_value else flags).append(option)
        index += 2 if takes_value else 1
        need(index >= len(spec) or spec[index] != ':',
             'Optional getopt argument requires a dedicated parser')
    return (tuple(ch for ch in flags if ch not in ambiguous),
            tuple(ch for ch in arguments if ch not in ambiguous),
            tuple(sorted(ambiguous)))


def archive_grammars(archive, names):
    need(set(names) == set(MAIN_SOURCE), 'Expected the 14 archived OpenSSH tools')
    files = archive.data['source_snapshot']['files']
    found = {}
    for target in names:
        source = MAIN_SOURCE[target]
        source_sha = files[source]
        object_path = archive.object_path(source_sha)
        raw = object_path.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == source_sha,
             'Archived C source differs from its recorded digest')
        content = raw.decode('utf-8')
        matches = list(GETOPT.finditer(content))
        if target == 'ssh-keysign':
            need(not matches, 'Unexpected getopt parser in ssh-keysign')
            spec, line = '', None
        else:
            need(matches, 'No getopt parser found in pinned '+source)
            selected = matches[-1]  # sftp has earlier helper parsers.
            spec = ''.join(ast.literal_eval(m.group()) for m in
                           STRING.finditer(selected.group(1)))
            line = content.count('\n', 0, selected.start()) + 1
        flags, arguments, ambiguous = parse_spec(spec)
        found[target] = Grammar(target, source, source_sha, line, spec,
                                flags, arguments, ambiguous)
    validate_policy(found)
    return found


def validate_policy(grammars):
    need(set(grammars) == set(MAIN_SOURCE) == set(SAFE_FLAGS) ==
         set(SAFE_ARGUMENTS), 'Native probe policy has incomplete target coverage')
    for target, grammar in grammars.items():
        allowed = SAFE_FLAGS[target]
        need(len(allowed) == len(set(allowed)) and set(allowed) <= set(grammar.flags),
             'Safe flag policy diverged from pinned getopt grammar: '+target)
        for option, kind, values, prefix in SAFE_ARGUMENTS[target]:
            need(option in grammar.arguments and kind in
                 ('path', 'number', 'config', 'query') and values,
                 'Safe argument policy diverged from pinned getopt grammar: '+target)
            need(all(type(value) is str and value and '\x00' not in value and
                     not re.search(r'[;&|`$<>\\\n\r]', value) for value in values),
                 'Unsafe generated option value')
            need(all(item.startswith('-') and len(item) == 2 and
                     item[1] in allowed for item in prefix),
                 'Terminating prefix is not a safe parser flag')


def atoms(grammar):
    """One-atom invocations only; no Cartesian product is materialized."""
    target = grammar.target
    no_args = [((), 'no-args')] if target in SAFE_NO_ARGUMENTS else []
    # ssh-agent's version mode is its only approved non-daemon probe; retain
    # one isolated version invocation even though the baseline also uses -V.
    flags = [((('-'+ch),), 'flag:'+ch) for ch in grammar.flags
             if ch in SAFE_FLAGS[target] and
             (ch not in 'hV' or (target == 'ssh-agent' and ch == 'V'))]
    arguments = [(tuple(prefix) + ('-'+ch, value),
                  'arg:'+ch+':'+kind+':'+str(index))
                 for ch, kind, values, prefix in SAFE_ARGUMENTS[target]
                 for index, value in enumerate(values)]
    return (tuple(no_args), tuple(flags), tuple(arguments))
