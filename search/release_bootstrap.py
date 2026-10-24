"""Fetch and install the latest complete prebuilt OpenSSH Lean search release.

The normal autonomous-search command calls ensure_ready() on first use. Its
download cache and installed data live under the ignored local/ and work/
directories; no model rebuild or GitHub CLI is required.
"""
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import sqlite3
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from common import WORKSPACE, need, sha


REPOSITORY = 'mingusb/openssh-lean'
API = 'https://api.github.com/repos/' + REPOSITORY
MARKER = WORKSPACE/'local/release/turnkey.json'
USER_AGENT = 'openssh-lean-release-bootstrap/1'
CHUNK = 4*1024*1024


def log(message):
    print('[openssh-lean] ' + message, flush=True)


def request_json(url):
    request = Request(url, headers={'User-Agent': USER_AGENT,
                                     'Accept': 'application/vnd.github+json'})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def release_assets():
    release = request_json(API+'/releases/latest')
    need(release.get('draft') is False and release.get('prerelease') is False,
         'Latest GitHub release is not public and stable')
    tag = release['tag_name']
    need(type(tag) is str and tag and Path(tag).name == tag and '/' not in tag,
         'Unsafe release tag')
    assets = request_json(API+'/releases/'+str(release['id'])+'/assets?per_page=100')
    need(type(assets) is list and len(assets) < 100,
         'Release asset listing is incomplete')
    found = {}
    for asset in assets:
        name = asset['name']
        need(type(name) is str and Path(name).name == name and name not in found,
             'Unsafe or duplicate release asset name')
        found[name] = asset
    return tag, found


def _download(url, path, length, digest=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.stat().st_size == length and (digest is None or sha(path) == digest):
        return path
    pending = path.with_name(path.name+'.part')
    for attempt in range(5):
        position = pending.stat().st_size if pending.exists() else 0
        if position > length:
            pending.unlink()
            position = 0
        headers = {'User-Agent': USER_AGENT, 'Accept': 'application/octet-stream'}
        if position:
            headers['Range'] = 'bytes='+str(position)+'-'
        try:
            with urlopen(Request(url, headers=headers), timeout=120) as response:
                append = position > 0 and response.status == 206
                if append:
                    need(response.headers.get('Content-Range','').startswith('bytes '+str(position)+'-'),
                         'Release server returned the wrong resumed byte range')
                with pending.open('ab' if append else 'wb') as output:
                    while data := response.read(CHUNK):
                        output.write(data)
            if pending.stat().st_size == length and (digest is None or sha(pending) == digest):
                os.replace(pending, path)
                return path
            if pending.stat().st_size == length:
                pending.unlink()
                raise RuntimeError('Release asset failed its SHA-256 check: '+path.name)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            if attempt == 4:
                raise RuntimeError('Could not download '+path.name+': '+str(error)) from error
        time.sleep(min(2**attempt, 8))
    raise RuntimeError('Incomplete release asset: '+path.name)


def asset_file(name, description, download_dir, remote):
    need(Path(name).name == name and name in remote, 'Missing release asset: '+name)
    expected_size = description.get('bytes', remote[name]['size'])
    need(type(expected_size) is int and expected_size == remote[name]['size'],
         'Release asset has an unexpected size: '+name)
    digest = description.get('sha256')
    api_digest = remote[name].get('digest')
    if api_digest:
        need(api_digest.startswith('sha256:') and
             (digest is None or api_digest == 'sha256:'+digest),
             'Release API hash differs for '+name)
        digest = digest or api_digest.split(':',1)[1]
    need(digest is None or (len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)),
         'Invalid asset SHA-256: '+name)
    return _download(remote[name]['browser_download_url'], download_dir/name,
                     expected_size, digest)


def _safe_target(name, link):
    need(link and not link.startswith('/'), 'Unsafe archive link: '+name)
    parts = list(PurePosixPath(name).parent.parts)
    for part in PurePosixPath(link).parts:
        if part == '..':
            need(bool(parts), 'Archive link escapes installation')
            parts.pop()
        elif part not in ('', '.'):
            parts.append(part)
    need(bool(parts), 'Archive link escapes installation')


def extract(asset, root, allowed):
    """Extract only regular files, directories, and contained relative symlinks."""
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(asset, 'r:gz') as tar:
        for member in tar:
            raw = member.name.rstrip('/')
            name = PurePosixPath(raw)
            need(raw and not raw.startswith('/') and '..' not in name.parts and
                 str(name) == raw and name.parts[0] in allowed,
                 'Unsafe release archive member: '+member.name)
            destination = root.joinpath(*name.parts)
            for parent in list(destination.parents)[:-1]:
                if parent == root.parent:
                    break
                need(not parent.is_symlink(), 'Archive member crosses a symlink')
            destination.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                need(not destination.is_symlink() and
                     (not destination.exists() or destination.is_dir()),
                     'Archive directory conflicts with existing file')
                destination.mkdir(exist_ok=True)
            elif member.isfile():
                need(not destination.exists() and not destination.is_symlink(),
                     'Duplicate archive member: '+raw)
                source = tar.extractfile(member)
                need(source is not None, 'Archive file has no payload')
                with destination.open('xb') as output:
                    shutil.copyfileobj(source, output, CHUNK)
                need(destination.stat().st_size == member.size,
                     'Archive member length changed: '+raw)
                destination.chmod(member.mode & 0o755)
            elif member.issym():
                _safe_target(raw, member.linkname)
                need(not destination.exists() and not destination.is_symlink(),
                     'Duplicate archive link: '+raw)
                destination.symlink_to(member.linkname)
            else:
                raise RuntimeError('Unsupported archive member: '+raw)


def _index(parts, receipt, output, description):
    digest = hashlib.sha256()
    length = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as target:
        for entry, source in zip(description['parts'], parts, strict=True):
            need(entry['raw_offset'] == length, 'Index part offset differs')
            part_digest = hashlib.sha256()
            part_length = 0
            with gzip.open(source, 'rb') as stream:
                while data := stream.read(CHUNK):
                    target.write(data)
                    digest.update(data)
                    part_digest.update(data)
                    part_length += len(data)
            need(part_length == entry['raw_bytes'] and
                 part_digest.hexdigest() == entry['raw_sha256'],
                 'Index part changed: '+source.name)
            length += part_length
    need(length == description['sqlite_bytes'] and
         digest.hexdigest() == description['sqlite_sha256'],
         'Restored index differs from the release')
    shutil.copyfile(receipt, output.parent/'receipt.json')
    db = sqlite3.connect(output.as_uri()+'?mode=ro', uri=True)
    try:
        need(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok',
             'Restored SQLite index failed quick_check')
        need(db.execute('SELECT count(*) FROM models').fetchone()[0] == 14 and
             db.execute('SELECT count(*) FROM fragments').fetchone()[0] ==
                 description['fragments'],
             'Restored index does not contain the complete model cohort')
    finally:
        db.close()


def _already_ready():
    required = (WORKSPACE/'local/models/current/manifest.json',
                WORKSPACE/'local/search/index/index.sqlite',
                WORKSPACE/'local/runtime/signal-search/build.json',
                WORKSPACE/'work/lean-4.32.2-linux/bin/lean',
                WORKSPACE/'work/reference-source/scp')
    if not all(path.is_file() for path in required):
        return False
    if MARKER.is_file():
        manifest = json.loads(MARKER.read_bytes())
        need(sha(required[0]) == manifest['archive_manifest_sha256'],
             'Installed release manifest changed')
    else:
        # A producer checkout has a local build receipt. A failed relocated
        # installation must never be mistaken for that original build.
        build = json.loads(required[2].read_bytes())
        imports = build.get('import_artifacts') or {}
        need(imports, 'Prebuilt search worker has no semantic dependencies')
        if not all(Path(path).is_relative_to(WORKSPACE) for path in imports):
            return False
    return True


def ensure_ready(assets_dir=None):
    """Install the latest release once; subsequent search starts use the local copy."""
    if _already_ready():
        return
    need(platform.system() == 'Linux' and platform.machine() == 'x86_64',
         'Prebuilt release currently requires Linux x86_64')
    cache = WORKSPACE/'local/downloads'
    cache.mkdir(parents=True, exist_ok=True)
    with (cache/'.bootstrap.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _already_ready():
            return
        if assets_dir is None:
            tag, remote = release_assets()
            downloads = cache/tag
            downloads.mkdir(exist_ok=True)
            turnkey_path = asset_file('turnkey.json', {}, downloads, remote)
            models_path = asset_file('models.json', {}, downloads, remote)
        else:
            downloads = Path(assets_dir).resolve(strict=True)
            turnkey_path, models_path = downloads/'turnkey.json', downloads/'models.json'
            need(turnkey_path.is_file() and models_path.is_file(),
                 'Local release assets are incomplete')
            remote = None
            tag = 'local-test'
        turnkey = json.loads(turnkey_path.read_bytes())
        models = json.loads(models_path.read_bytes())
        need(turnkey.get('schema') == 1 and
             turnkey.get('kind') == 'openssh-lean-turnkey-release' and
             turnkey.get('platform') == 'linux-x86_64-ubuntu-26.04' and
             models.get('archive_manifest_sha256') == turnkey['archive_manifest_sha256'] and
             len(models['models']) == 14,
             'Latest release is not a complete compatible search package')
        def get(row):
            name = row['asset']
            if remote is None:
                path = downloads/name
                need(path.is_file() and
                     (row.get('bytes') is None or path.stat().st_size == row['bytes']) and
                     sha(path) == row['sha256'], 'Local release asset differs: '+name)
                return path
            log('Downloading '+name)
            return asset_file(name, row, downloads, remote)
        metadata = get(turnkey['archive_metadata'])
        object_parts = [get(row) for row in turnkey['archive_objects']]
        model_parts = [get(row) for row in models['models']]
        index_parts = [get(row) for row in models['search_index']['parts']]
        receipt = get(dict(asset=models['search_index']['receipt_asset'],
                           sha256=models['search_index']['receipt_sha256']))
        runtime_parts = [get(row) for row in turnkey['prebuilt_runtime']]
        stage = cache/('.installing-'+tag)
        need(stage.resolve().is_relative_to(cache.resolve()), 'Unsafe installation staging path')
        if stage.exists():
            shutil.rmtree(stage)
        archive_stage = stage/'archive'
        runtime_stage = stage/'runtime'
        log('Restoring full model archive')
        extract(metadata, archive_stage,
                {'manifest.json','manifest.sha256','verification.json','README.md','tools'})
        for part in object_parts:
            extract(part, archive_stage, {'objects'})
        manifest = json.loads((archive_stage/'manifest.json').read_bytes())
        need(sha(archive_stage/'manifest.json') == turnkey['archive_manifest_sha256'] and
             len(manifest['objects']) == turnkey['expected_archive_objects'],
             'Restored archive manifest differs')
        for row in models['models']:
            digest = row['sha256']
            destination = archive_stage/'objects'/digest[:2]/digest
            need(not destination.exists() and digest in manifest['objects'],
                 'Duplicate or unknown model object')
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.link(downloads/row['asset'], destination)
        from model_archive import Archive
        archive = Archive(archive_stage, turnkey['archive_manifest_sha256'])
        need(archive.verify()['passed'], 'Restored archive did not verify')
        log('Restoring prebuilt search index')
        _index(index_parts, receipt, stage/'index/index.sqlite', models['search_index'])
        log('Restoring prebuilt runtime')
        for part in runtime_parts:
            extract(part, runtime_stage, {'work','local'})
        for relative in turnkey['runtime_paths']:
            source = runtime_stage/relative
            destination = WORKSPACE/relative
            need(source.exists() or source.is_symlink(),
                 'Runtime asset omitted '+relative)
            need(not destination.exists() and not destination.is_symlink(),
                 'Existing runtime path blocks release install: '+relative)
        targets = [('local/models/current', archive_stage),
                   ('local/search/index', stage/'index')]
        targets += [(relative, runtime_stage/relative)
                    for relative in turnkey['runtime_paths']]
        installed = []
        try:
            for relative, source in targets:
                destination = WORKSPACE/relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)
                installed.append(destination)
            MARKER.parent.mkdir(parents=True, exist_ok=True)
            MARKER.write_text(json.dumps(turnkey, indent=2, sort_keys=True)+'\n')
            from signal_search import checked_build
            from native_signal_replay import native_binary
            checked_build()
            archive = Archive(WORKSPACE/'local/models/current',
                              turnkey['archive_manifest_sha256'])
            for target in archive.data['models']:
                native_binary(archive, target)
        except BaseException:
            MARKER.unlink(missing_ok=True)
            for destination in reversed(installed):
                if destination.is_dir() and not destination.is_symlink():
                    shutil.rmtree(destination)
                else:
                    destination.unlink(missing_ok=True)
            raise
        log('Release installed and verified: '+tag)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets-dir', type=Path)
    args = parser.parse_args()
    ensure_ready(args.assets_dir)
