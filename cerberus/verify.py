"""Verify the pinned source patch against a clean Cerberus base."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "cerberus/source-package.json"
FORK = ROOT / "local/cerberus-lean"

def run(*args, env=None):
    return subprocess.check_output(["git", "-C", str(FORK), *args], env=env).decode().strip()

def verify():
    package = json.loads(PACKAGE.read_text(encoding="utf-8"))
    if package.get("schema") != 1:
        raise RuntimeError("Unknown source package schema")
    source = package["cerberus"]
    base = source["base_commit"]
    patch = ROOT / source["patch"]
    manifest = ROOT / source["changed_files_manifest"]
    if hashlib.sha256(patch.read_bytes()).hexdigest() != source["patch_sha256"]:
        raise RuntimeError("Patch hash differs")
    if not (FORK / ".git").exists():
        raise RuntimeError("Fetch the pinned Cerberus base into local/cerberus-lean")
    run("cat-file", "-e", base + "^{commit}")
    with tempfile.TemporaryDirectory(prefix="cerberus-source-check-") as temp:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temp) / "index"))
        run("read-tree", base, env=env)
        run("apply", "--cached", "--whitespace=nowarn", str(patch), env=env)
        tree = run("write-tree", env=env)
        names = [name for name in subprocess.check_output(
            ["git", "-C", str(FORK), "diff", "--cached", "--name-only", "-z", base],
            env=env,
        ).decode().split("\0") if name]
    expected = manifest.read_text(encoding="utf-8").splitlines()
    if tree != source["patched_tree"] or names != expected or len(names) != source["changed_files"]:
        raise RuntimeError("Patch does not reconstruct the recorded source tree and file list")
    print("Verified Cerberus source patch:", tree, "with", len(names), "changed files")

if __name__ == "__main__":
    verify()
