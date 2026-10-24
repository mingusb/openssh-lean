"""Hash-check a Cabs call and its exact matching original-C byte span.

This proves membership in the saved parser AST and equality of a simple call's
tokens with pinned original source bytes. It does not prove that a Core node was
translated from this Cabs node, that the call is reachable, or that it faults.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

from common import WORKSPACE, need
from model_archive import Archive
from source_locations import file_key, read_verified


DEFAULT_ARCHIVE = WORKSPACE/'local/models/current'
DEFAULT_WITNESSES = WORKSPACE/'local/search/catalog/source-call-witnesses'
TOKEN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[(),]')
IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')


class NoExactMapping(RuntimeError):
    """The checked artifacts do not support this narrow expression mapping."""


def require_match(condition, message):
    if not condition:
        raise NoExactMapping(message)


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def walk(node, path):
    """Yield every object with a reproducible path through one Cabs body."""
    stack = [(node, path)]
    while stack:
        value, address = stack.pop()
        if isinstance(value, dict):
            yield address, value
            stack.extend((item, address+[key]) for key, item in reversed(list(value.items()))
                         if isinstance(item, (dict, list)))
        elif isinstance(value, list):
            stack.extend((item, address+[index]) for index, item in
                         reversed(list(enumerate(value))) if isinstance(item, (dict, list)))


def function_name(definition):
    """Accept a direct C function declarator, not an incidental parameter name."""
    direct = definition['declarator']['direct']
    if direct['tag'] != 'DDecl_function' or \
            direct['direct']['tag'] != 'DDecl_identifier':
        return None
    return direct['direct']['id']['name']


def simple_callee(expression):
    call = expression.get('expr', {})
    if call.get('tag') != 'CabsEcall':
        return None
    callee = call.get('fun', {}).get('expr', {})
    if callee.get('tag') != 'CabsEident':
        return None
    return callee['id']['name']


def simple_argument(expression):
    inner = expression['expr']
    if inner['tag'] == 'CabsEident':
        name = inner['id']['name']
        require_match(IDENT.fullmatch(name), 'Unsupported C identifier in call witness')
        return name
    if inner['tag'] == 'CabsEconst' and inner['val']['tag'] == 'CabsInteger_const':
        value = inner['val']['val'][0]
        require_match(type(value) is str and re.fullmatch(r'[0-9]+', value),
                      'Only plain decimal C integer arguments are supported')
        return value
    raise NoExactMapping('Call witness requires simple identifier or decimal arguments')


def same_line_region(location, source, line):
    require_match(location['tag'] == 'Loc_region' and location['cursor'] == 'NoCursor',
                  'Call has no plain parser source region')
    begin, end = location['begin'], location['end']
    require_match(begin['file'] == end['file'] == source and
                  begin['line'] == end['line'] == line and
                  type(begin['col']) is int and type(end['col']) is int and
                  1 <= begin['col'] < end['col'],
                  'Call parser region is not a positive span on the selected C line')
    return begin['col'], end['col']


def lex_simple_call(raw):
    """Reject punctuation/comments/macros outside the supported call grammar."""
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError as error:
        raise NoExactMapping('Original C expression is not plain ASCII') from error
    tokens, cursor = [], 0
    for match in TOKEN.finditer(text):
        require_match(not text[cursor:match.start()].strip(),
                      'Original C expression contains unsupported tokens')
        tokens.append(match.group())
        cursor = match.end()
    require_match(not text[cursor:].strip(), 'Original C expression has unsupported suffix')
    return tokens, text


def exact_original_span(source_bytes, line, start_col, end_col):
    lines = source_bytes.split(b'\n')
    require_match(1 <= line <= len(lines), 'C line is outside the pinned source')
    line_bytes = lines[line-1]
    require_match(end_col-1 <= len(line_bytes), 'Parser column is outside the C line')
    line_start = sum(len(value)+1 for value in lines[:line-1])
    start, end = line_start+start_col-1, line_start+end_col-1
    require_match(0 <= start < end <= len(source_bytes), 'Invalid original-C byte span')
    return dict(start=start, end=end, bytes=source_bytes[start:end],
                line_sha256=digest(line_bytes))


def build_call_witness(archive, target, source, caller, callee, line):
    """Verify one unique simple Cabs call and the exact original-C bytes."""
    need(type(line) is int and line > 0 and all(
         type(name) is str and IDENT.fullmatch(name)
         for name in (caller, callee)), 'Invalid C call selector')
    need(type(source) is str and source and file_key(source) == source and
         not PurePosixPath(source).is_absolute() and '\\' not in source,
         'Select one normalized relative translation-unit path')
    model = archive.model(target)
    binding = archive.read_json(model['binding_sha256'])
    candidates = [row for row in binding['frontend_order'] if row['source'] == source]
    require_match(len(candidates) == 1, 'C source unit is missing or ambiguous')
    unit = candidates[0]
    archive_c = read_verified(
        archive.resolve(unit['original_path'], unit['original_sha256']),
        unit['original_sha256'])
    live_path = Path(unit['original_path'])
    need(not live_path.is_symlink(), 'Pinned original C path is a symlink')
    live_c = read_verified(live_path, unit['original_sha256'])
    need(live_c == archive_c, 'Live and archived original C bytes differ')
    cabs = archive.read_json(unit['cabs_sha256'])
    need(cabs['tag'] == 'TUnit', 'Archived parser tree is not a C translation unit')
    functions = [(index, row['def']) for index, row in enumerate(cabs['decls'])
                 if row.get('tag') == 'EDecl_func' and row.get('def', {}).get('tag') == 'FunDef'
                 and function_name(row['def']) == caller]
    require_match(len(functions) == 1, 'C caller definition is missing or ambiguous')
    index, definition = functions[0]
    matches = []
    for address, node in walk(definition['body'], ['decls', index, 'def', 'body']):
        if node.get('tag') != 'CabsExpression' or simple_callee(node) != callee:
            continue
        location = node.get('loc', {})
        begin, end = location.get('begin', {}), location.get('end', {})
        if begin.get('file') == source and begin.get('line') == line and \
                end.get('file') == source and end.get('line') == line:
            matches.append((address, node))
    require_match(len(matches) == 1, 'C call expression is missing or ambiguous on the selected line')
    address, expression = matches[0]
    start_col, end_col = same_line_region(expression['loc'], source, line)
    args = [simple_argument(arg) for arg in expression['expr']['args']]
    expected_tokens = [callee, '(']
    for position, arg in enumerate(args):
        if position:
            expected_tokens.append(',')
        expected_tokens.append(arg)
    expected_tokens.append(')')
    span = exact_original_span(archive_c, line, start_col, end_col)
    tokens, text = lex_simple_call(span['bytes'])
    require_match(tokens == expected_tokens,
                  'Parsed Cabs call does not match the exact original-C expression bytes')
    core = dict(archive_manifest_sha256=archive.manifest_sha256,
        target=target, binding_sha256=model['binding_sha256'],
        source=source, caller=caller, callee=callee, line=line,
        archived_cabs_sha256=unit['cabs_sha256'],
        original_c_path=unit['original_path'],
        original_c_sha256=unit['original_sha256'],
        cabs=dict(ast_path=address, expression_sha256=digest(packed(expression).encode()),
                  region=expression['loc'], argument_tokens=args),
        original_c=dict(byte_span=dict(start=span['start'], end=span['end']),
                        text=text, expression_sha256=digest(span['bytes']),
                        line_sha256=span['line_sha256'], tokens=tokens),
        checks=dict(archived_parser_tree_hash_verified=True,
                    archived_original_c_hash_verified=True,
                    live_original_c_hash_verified=True,
                    caller_ast_membership_verified=True,
                    unique_call_on_selected_line_verified=True,
                    cabs_original_c_expression_bytes_match=True,
                    cabs_to_core_translation_proved=False,
                    core_dynamic_reachability_proved=False,
                    native_fault_correspondence_proved=False),
        scope='Exact simple C call expression in pinned original bytes and saved Cabs AST; '
              'not a Core translation or execution theorem')
    return dict(id=digest(packed(core).encode()), **core)


def verify_call_witness(archive, record):
    need(type(record) is dict and type(record.get('id')) is str,
         'C call witness record is missing its identity')
    expected = build_call_witness(
        archive, record['target'], record['source'], record['caller'],
        record['callee'], record['line'])
    need(record == expected, 'C call witness differs from the checked archive and C bytes')
    return expected


def save_call_witness(directory, record):
    """Publish an immutable hash-named JSON file after full verification."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory/(record['id']+'.json')
    data = (packed(record)+'\n').encode()
    if path.exists():
        need(path.read_bytes() == data, 'Existing C call witness differs')
        return path
    fd, temporary = tempfile.mkstemp(prefix='.call-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            need(path.read_bytes() == data, 'Concurrent C call witness differs')
    finally:
        os.unlink(temporary)
    return path


def ensure_source_call_witness(target, source_file, source_line, symbol, catalog_dir):
    """Produce or verify a deterministic source witness in one catalog."""
    archive = Archive(DEFAULT_ARCHIVE)
    try:
        record = build_call_witness(
            archive, target, source_file, symbol, symbol, source_line)
    except NoExactMapping:
        return None
    save_call_witness(Path(catalog_dir)/'source-call-witnesses', record)
    return record['id']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=DEFAULT_ARCHIVE)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('--target', required=True)
    create.add_argument('--source', required=True)
    create.add_argument('--caller', required=True)
    create.add_argument('--callee', required=True)
    create.add_argument('--line', type=int, required=True)
    create.add_argument('--directory', type=Path, default=DEFAULT_WITNESSES)
    verify = commands.add_parser('verify')
    verify.add_argument('file', type=Path)
    args = parser.parse_args()
    archive = Archive(args.archive)
    if args.command == 'create':
        record = build_call_witness(
            archive, args.target, args.source, args.caller, args.callee, args.line)
        file = save_call_witness(args.directory, record)
        print(packed(dict(id=record['id'], path=str(file),
                          original_c=record['original_c'],
                          scope=record['scope'])))
    else:
        record = json.loads(args.file.read_text())
        verify_call_witness(archive, record)
        print(packed(dict(id=record['id'], status='verified', path=str(args.file))))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(packed(dict(status='error', error=str(error))))
        raise SystemExit(2)
