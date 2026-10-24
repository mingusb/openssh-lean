# OpenSSH Lean

[![OpenSSH Lean project overview](project-overview.png)](https://brianmingus.com/papers/openssh-lean.pdf)

Source for the OpenSSH Lean research project. The linked white paper is the
project documentation. The Lean model is at the root; the autonomous crash
search is in `search/`.

To generate the pinned 14-model archive on Linux x86_64, install Git, Python 3.11+,
opam, OCaml 5.4.0, a C/C++ build toolchain, Autotools, ccache, zstd, and a
working systemd user scope. Then run:

```sh
python3 pipeline/build_models.py all --jobs 4
```

The command fetches the pinned OpenSSH, Cerberus, Lem, and Lean sources,
builds the translator and reference, prepares the C input receipts, exports
the models, and verifies the archive at `local/models/current`. `work/`,
`outputs/`, and `local/` contain generated local state and are excluded from
Git. The ~7 GB archive is generated locally; it is not in this repository.

To prepare the autonomous search after the archive is built, also install
bubblewrap, strace, and gdb. Then run:

```sh
python3 search/build_signal_search.py
python3 search/core_index.py build
python3 search/autonomous_search_loop.py run
```

The search index is generated under `local/search/index`. It can be rebuilt
from the verified archive; the release also provides a prebuilt copy bound to
that archive's exact manifest.

The source checks in CI verify the package and portable tests. They do not
perform the full multi-gigabyte model build.
