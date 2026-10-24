"""Persistent native compilation cache around the verified host C compiler."""
import json
import os
from pathlib import Path
from build_guard import need, sha

COMPILER = Path("/usr/bin/cc")
CACHE = Path("/usr/bin/ccache")
DRIVER = Path("/usr/lib/ccache/cc")


def settings(workspace, runtime):
    return {
        "LEAN_CC": str(DRIVER),
        "CCACHE_CONFIGPATH": "/dev/null",
        "CCACHE_COMPILER": str(COMPILER),
        "CCACHE_COMPILERCHECK": "content",
        "CCACHE_DIR": str(Path(runtime) / "native-compiler-cache"),
        "CCACHE_MAXSIZE": "0",
        "CCACHE_MAXFILES": "0",
        "CCACHE_EXTRAFILES": str(Path(workspace) / "work/toolchain-lock.json"),
    }


def identity(workspace, runtime):
    need(CACHE.is_file() and DRIVER.is_file(),
         "Native compiler cache is missing; install ccache without changing the pinned compiler.")
    need(DRIVER.resolve() == CACHE.resolve(), "Unexpected compiler-cache driver")
    return {
        "settings": settings(workspace, runtime),
        "files": {str(p): {"resolved": str(p.resolve()), "sha256": sha(p)}
                  for p in (COMPILER, CACHE, DRIVER)},
    }


def configure(workspace, runtime):
    profile = identity(workspace, runtime)
    # Process-local configuration: do not inherit remote storage, compiler
    # substitution, relaxed correctness checks or eviction limits.
    for name in list(os.environ):
        if name.startswith("CCACHE_"):
            del os.environ[name]
    os.environ.update(profile["settings"])
    return profile


if __name__ == "__main__":
    import sys
    print(json.dumps(identity(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
