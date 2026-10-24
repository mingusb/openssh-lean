"""Lazy, deterministic value families for local native C probes.

The source-backed option grammar supplies the option names.  This module
supplies values and byte streams one at a time; it never constructs an option
cross product or gives a generated invocation a host or shell operand.
"""

import base64
import hashlib
import struct

from native_input_grammar import SAFE_ARGUMENTS, validate_policy


# Protocol readers can consume stdin without a network endpoint.  Other tools
# still receive the shared baseline and safe option probes; a stdin mode is not
# claimed when the selected invocation would exit before reading it.
STDIN_TARGETS = frozenset((
    'sftp-server', 'ssh-keysign', 'ssh-pkcs11-helper', 'ssh-sk-helper',
))

# Appended after the original value roster. The first ten slots retain their
# original meanings and cursors when an existing frontier is migrated.
EXTENDED_MODES = (
    ('ssh-add', 'duration:t'),
    ('ssh-agent', 'duration:t'),
    ('ssh-keygen', 'stdin:fingerprint'),
    ('sshd-auth', 'number:u'),
    ('sshd-session', 'number:p'),
    ('sshd-session', 'number:o:MaxStartups'),
)
_DURATION_UNITS = ('', 's', 'm', 'h', 'd', 'w')

# Reach familiar C integer edges early, then enumerate signed integers with
# no largest value.  The finite prefix is a priority order, not a search bound.
_PRIORITY_INTEGERS = tuple(dict.fromkeys((
    0, 1, -1, 2, -2, 7, 8, 15, 16, 31, 32, 63, 64,
    127, 128, 255, 256, 257, 1023, 1024,
    32767, 32768, 65534, 65535, 65536, 65537,
    (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 1 << 32,
    (1 << 63) - 1, 1 << 63,
    -128, -129, -32768, -32769, -(1 << 31),
    -(1 << 63),
)))
_BYTE_FAMILIES = (
    b'\x00', b'\xff', b'A', b'\n', b'0',
    b'SSH-2.0-local-probe\r\n',
    bytes(range(256)),
    None,  # Big-endian, length-prefixed packet-shaped input.
)
_PRIORITY_LENGTHS = (
    1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
    63, 64, 65, 127, 128, 129, 255, 256, 257,
    511, 512, 513, 1023, 1024, 1025,
    4095, 4096, 4097, 65535, 65536, 65537,
)


def integer_at(index):
    """Return the indexed signed decimal value; every integer appears later."""
    if type(index) is not int or index < 0:
        raise ValueError('Value index must be a nonnegative integer')
    if index < len(_PRIORITY_INTEGERS):
        return _PRIORITY_INTEGERS[index]
    rest = index - len(_PRIORITY_INTEGERS)
    magnitude = rest // 2 + 3
    return magnitude if rest % 2 == 0 else -magnitude


def _repeat_to_length(pattern, length):
    if not pattern:
        raise ValueError('Byte family cannot be empty')
    return (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]


def length_at(index):
    """Visit framing and allocation edges first, then every remaining length."""
    if type(index) is not int or index < 0:
        raise ValueError('Length index must be a nonnegative integer')
    if index < len(_PRIORITY_LENGTHS):
        return _PRIORITY_LENGTHS[index]
    length = index - len(_PRIORITY_LENGTHS) + 1
    for selected in _PRIORITY_LENGTHS:
        if selected <= length:
            length += 1
    return length


def stdin_at(index):
    """Enumerate finite byte inputs in gradually increasing lengths."""
    if type(index) is not int or index < 0:
        raise ValueError('Value index must be a nonnegative integer')
    family = index % len(_BYTE_FAMILIES)
    length = length_at(index // len(_BYTE_FAMILIES))
    pattern = _BYTE_FAMILIES[family]
    if pattern is not None:
        return _repeat_to_length(pattern, length)
    # The first four bytes model a network-order payload length, including
    # intentionally short/truncated prefixes at the beginning of the search.
    declared = max(0, length - 4)
    header = declared.to_bytes(max(4, (declared.bit_length() + 7) // 8), 'big')
    return (header + b'\x00' * max(0, length - 4))[:length]


def duration_at(index):
    """Exercise convtime's numeric and unit branches without a maximum index."""
    if type(index) is not int or index < 0:
        raise ValueError('Value index must be a nonnegative integer')
    number = integer_at(index // len(_DURATION_UNITS))
    return str(number) + _DURATION_UNITS[index % len(_DURATION_UNITS)]


def _wire_string(value):
    return struct.pack('>I', len(value)) + value


def fingerprint_stdin_at(index):
    """Mix valid public keys, host-prefixed keys, and malformed input."""
    if type(index) is not int or index < 0:
        raise ValueError('Value index must be a nonnegative integer')
    family, serial = index % 4, index // 4
    if family == 1:
        return stdin_at(serial)
    key = hashlib.sha256(str(serial).encode('ascii')).digest()
    blob = _wire_string(b'ssh-ed25519') + _wire_string(key)
    if family == 2:
        blob = blob[:max(0, len(blob) - 1 - serial % 32)]
    line = b'ssh-ed25519 ' + base64.b64encode(blob) + b' local-probe\n'
    return b'local-probe ' + line if family == 3 else line


def _validate_extended_modes(grammars):
    expected = {
        'ssh-add': (('t', 'argument'), ('l', 'flag')),
        'ssh-agent': (('t', 'argument'), ('V', 'flag')),
        'ssh-keygen': (('f', 'argument'), ('l', 'flag')),
        'sshd-auth': (('u', 'argument'), ('V', 'flag')),
        'sshd-session': (('p', 'argument'), ('o', 'argument'),
                         ('V', 'flag')),
    }
    for target, required in expected.items():
        grammar = grammars[target]
        for option, kind in required:
            choices = grammar.arguments if kind == 'argument' else grammar.flags
            if option not in choices:
                raise ValueError('Value mode diverged from pinned C parser: '+target)


def modes(grammars):
    """Return source-validated parameter streams in stable target order."""
    validate_policy(grammars)
    result = []
    for target in sorted(grammars):
        for option, kind, _values, _prefix in SAFE_ARGUMENTS[target]:
            if kind == 'number':
                result.append((target, 'number:' + option))
        if target in STDIN_TARGETS:
            result.append((target, 'stdin'))
    _validate_extended_modes(grammars)
    result.extend(EXTENDED_MODES)
    return tuple(result)


def candidate(target, mode, index):
    """Produce exactly one local invocation with a stable origin label."""
    if type(index) is not int or index < 0:
        raise ValueError('Value index must be a nonnegative integer')
    if target not in SAFE_ARGUMENTS:
        raise ValueError('Unknown native target')
    if (target, mode) == ('ssh-add', 'duration:t'):
        return ('-t', duration_at(index), '-l'), b'', \
            'value:duration:t:' + str(index)
    if (target, mode) == ('ssh-agent', 'duration:t'):
        return ('-t', duration_at(index), '-V'), b'', \
            'value:duration:t:' + str(index)
    if (target, mode) == ('ssh-keygen', 'stdin:fingerprint'):
        return ('-l', '-f', '-'), fingerprint_stdin_at(index), \
            'value:stdin:fingerprint:' + str(index)
    if (target, mode) == ('sshd-auth', 'number:u'):
        return ('-u', str(integer_at(index)), '-V'), b'', \
            'value:number:u:' + str(index)
    if (target, mode) == ('sshd-session', 'number:p'):
        return ('-p', str(integer_at(index)), '-V'), b'', \
            'value:number:p:' + str(index)
    if (target, mode) == ('sshd-session', 'number:o:MaxStartups'):
        return ('-o', 'MaxStartups='+str(integer_at(index)), '-V'), b'', \
            'value:number:o:MaxStartups:' + str(index)
    if mode == 'stdin' and target in STDIN_TARGETS:
        return (), stdin_at(index), 'value:stdin:' + str(index)
    if mode.startswith('number:'):
        option = mode.removeprefix('number:')
        for allowed, kind, _values, prefix in SAFE_ARGUMENTS[target]:
            if kind == 'number' and option == allowed:
                argv = (*prefix, '-' + option, str(integer_at(index)))
                return argv, b'', ('value:number:' + option + ':' + str(index))
    raise ValueError('Unsupported local value mode for target')
