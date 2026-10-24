"""Current-artifact binding for direct shared floating-model execution."""
import os
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re

from varargs_publication import check_capture, check_command, identity_snapshot, need, read, sha

DIRECT = 'exact-float-model-check'
EXPECTED = {
    'ExactFloatTest': 'Exact floating model: 27 checks passed\n',
    'ExactFloatNativeOracle': 'Exact floating native oracle: 240 checks passed\n',
}
ENVIRONMENT = {'CERB_MEM_MAX': 'none', 'LEAN_NUM_THREADS': '2', 'LEAN_ABORT_ON_PANIC': '1'}


def sources(workspace, repo):
    return {
        'ExactFloatTest': repo/'lean_frontend/test/Unit/ExactFloatTest.lean',
        'ExactFloatNativeOracle': workspace/'outputs/openssh-lean/drafts/ExactFloatNativeOracle.lean',
    }


def search_paths(repo, lean):
    return [repo/'lean_frontend/.lake/packages/LemLib/lean-lib/.lake/build/lib/lean',
            repo/'lean_frontend/.lake/build/lib/lean', lean.parent.parent/'lib/lean']


class DependencyCache:
    """Bounded file-identity cache, used only under the checked workflow lease.

    Content changes invalidate ctime even if a writer restores size and mtime.
    Paths are still resolved through the live search path on every traversal.
    The publication default remains a fresh content read; callers explicitly
    opt in to this cache for repeated local smoke checks.
    """
    def __init__(self, path):
        self.path = path
        self.previous, self.current = {}, {}
        self.signatures = {}
        self.helper = sha(__file__)
        if path is not None:
            try:
                value = read(path)
                entries = value['entries']
                if (value['schema'] == 1 and value['helper'] == self.helper
                        and isinstance(entries, dict) and len(entries) <= 16384
                        and value['integrity'] == self.integrity(entries)):
                    self.previous = entries
            except (OSError, ValueError, KeyError, TypeError):
                pass

    @staticmethod
    def integrity(entries):
        return hashlib.sha256(json.dumps(entries, sort_keys=True,
                              separators=(',', ':')).encode()).hexdigest()

    @staticmethod
    def signature(path):
        stat = path.stat()
        return [stat.st_dev, stat.st_ino, stat.st_size,
                stat.st_mtime_ns, stat.st_ctime_ns]

    def file(self, path, metadata=False):
        key = str(path)
        before = self.signatures.get(key)
        if before is None:
            before = self.signature(path)
        previous = self.previous.get(key)
        if (isinstance(previous, dict) and previous.get('signature') == before
                and isinstance(previous.get('sha256'), str)
                and re.fullmatch(r'[0-9a-f]{64}', previous['sha256'])
                and (not metadata or isinstance(previous.get('description'), dict))):
            self.current[key] = previous
            return previous
        content = path.read_bytes()
        need(before == self.signature(path), 'compiled dependency changed while hashing '+key)
        entry = dict(signature=before, sha256=hashlib.sha256(content).hexdigest())
        if metadata:
            description = json.loads(content)
            entry['description'] = {key: description[key] for key in ('module', 'directImports')}
        self.current[key] = entry
        return entry

    def prefetch(self):
        # WSL metadata on the pinned Windows Lean library costs milliseconds
        # per call. Parallelize only these independent stat calls, not tests or
        # compilers. Live closure resolution below still discovers additions,
        # removals and newly shadowing modules; this list cannot define it.
        def inspect(name):
            try:
                return name, self.signature(Path(name))
            except OSError:
                return name, None  # A required live lookup will still fail.
        if self.previous:
            with ThreadPoolExecutor(max_workers=8) as executor:
                self.signatures = dict(executor.map(inspect, self.previous))

    def save(self):
        if self.path is None:
            return
        need(len(self.current) <= 16384, 'compiled dependency cache size limit')
        value = dict(schema=1, helper=self.helper, entries=self.current,
                     integrity=self.integrity(self.current))
        temporary = self.path.with_name(self.path.name+'.tmp')
        temporary.write_text(json.dumps(value, separators=(',', ':'))+'\n')
        temporary.replace(self.path)


def dependencies(repo, lean, modules=('Exact_float',), cache_path=None):
    """Resolve the actual compiled import closure, including implicit Init.

    The runner separately verifies Lake's search path; publication recomputes
    this manifest instead of trusting any report-supplied file list.
    """
    roots = search_paths(repo, lean)
    cache = DependencyCache(cache_path)
    cache.prefetch()
    directories = {}

    def present(path):
        # One live directory enumeration replaces repeated negative path
        # probes. File contents/signatures are still checked separately.
        parent = path.parent
        if parent not in directories:
            try:
                with os.scandir(parent) as entries:
                    directories[parent] = {entry.name: entry for entry in entries}
            except FileNotFoundError:
                directories[parent] = {}
        entry = directories[parent].get(path.name)
        return entry is not None and entry.is_file()

    pending, seen, files = [*modules, 'Init'], set(), {}
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', name),
             'compiled dependency module name '+name)
        relative = Path(*name.split('.'))
        base = next((root/relative for root in roots if present((root/relative).with_suffix('.olean'))), None)
        need(base is not None, 'compiled dependency '+name)
        metadata = base.with_suffix('.ilean')
        description = cache.file(metadata, metadata=True)['description']
        need(description['module'] == name, 'compiled dependency module identity '+name)
        for suffix in ('.olean', '.ilean', '.olean.private', '.olean.server'):
            path = base.with_suffix(suffix)
            if suffix in ('.olean', '.ilean') or present(path):
                files[str(path)] = (cache.current[str(path)] if path == metadata
                                    else cache.file(path))['sha256']
        for entry in description['directImports']:
            need(isinstance(entry, list) and len(entry) == 4 and isinstance(entry[0], str),
                 'compiled dependency import metadata '+name)
            pending.append(entry[0])
        seen.add(name)
    cache.save()
    return files


def snapshot(workspace, repo, lake, lean):
    project = workspace/'outputs/openssh-lean'
    files = [project/'patches/cerberus-gnu-keywords.patch',
             project/'drafts/check_exact_float_model.py',
             project/'scripts/exact_float_publication.py',
             project/'scripts/varargs_publication.py',
             project/'scripts/exercise_imported_c.py',
             repo/'scripts/capped', repo/'frontend/model/exact_float.lem',
             repo/'lean_frontend/generated/Exact_float.lean',
             repo/'lean_frontend/lean-toolchain', repo/'lean_frontend/lakefile.toml',
             repo/'lean_frontend/lake-manifest.json', lake, lean,
             *sources(workspace, repo).values()]
    files.extend(sorted((lean.parent.parent/'lib/lean').glob('*.so')))
    return {'runtime': identity_snapshot(repo), 'files': {str(path): sha(path) for path in files},
            'compiled_dependencies': dependencies(repo, lean)}


def commands(workspace, repo, lake, lean):
    return {'version': [str(lake), 'env', str(lean), '--version'],
            'paths': [str(lake), 'env', 'printenv', 'LEAN_PATH'],
            **{name: [str(lake), 'env', str(lean), '--run', str(path)]
               for name, path in sources(workspace, repo).items()}}


def version_matches(repo, result):
    expected = re.fullmatch(r'leanprover/lean4:v([^\s]+)',
                           (repo/'lean_frontend/lean-toolchain').read_text().strip())
    actual = re.fullmatch(r'Lean \(version ([^,\s)]+)(?:,[^\r\n]*)?\)\s*', result['stdout'])
    return bool(expected and actual and expected[1] == actual[1] and
                result['exit_code'] == 0 and not result['timeout'] and result['stderr'] == '')


def paths_match(repo, lean, result):
    return (result['exit_code'] == 0 and not result['timeout'] and result['stderr'] == '' and
            result['stdout'].strip().rstrip(os.pathsep).split(os.pathsep) ==
            [str(path) for path in search_paths(repo, lean)])


def validate_direct_float(report, workspace, repo, directory):
    workspace, repo, directory = Path(workspace), Path(repo), Path(directory)
    lake = workspace/'work/lean-4.32.2-linux/bin/lake'
    lean = workspace/'work/lean-4.32.2-linux/bin/lean'
    need(report['passed'] is True and report['full_suite'] is True and report['native_only'] is False,
         'complete direct floating execution required')
    need(report['required_environment'] == ENVIRONMENT, 'direct floating resource/panic policy')
    need(report['artifact_hashes_verified'] is True and
         report['identity_before'] == report['identity_after'] == snapshot(workspace, repo, lake, lean),
         'current direct floating engine/dependency/toolchain/source/patch identities')
    expected_commands = commands(workspace, repo, lake, lean)
    for lane in ('version', 'paths'):
        result = report[lane]
        check_capture(result, directory, 'toolchain', lane)
        check_command(result, expected_commands[lane], 'direct floating '+lane)
    need(version_matches(repo, report['version']), 'direct floating pinned Lean version')
    need(paths_match(repo, lean, report['paths']), 'direct floating exact import search path')
    need(len(report['cases']) == len(EXPECTED) and
         {row['case'] for row in report['cases']} == set(EXPECTED), 'both direct floating corpora')
    for row in report['cases']:
        name = row['case']
        need(row['passed'] is True, name+' execution passed')
        check_capture(row, directory, name, 'lean')
        check_command(row, expected_commands[name], name+' exact command')
        need(row['stdout'] == EXPECTED[name] and row['stderr'] == '', name+' exact positive receipt')
        need(row['source_sha256'] == sha(sources(workspace, repo)[name]), name+' current source')
