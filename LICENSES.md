# Licenses and attribution

Licensing is component-specific. This snapshot does not replace upstream notices
or grant a blanket license over every file.

- **Cerberus and the modified Cerberus Lean fork:** retain the original
  [LICENSE](https://github.com/OathTech/cerberus-lean/blob/c4284b08f80c4461f97d179896868106e510327e/LICENSE). It specifies BSD 2-clause terms with
  exceptions listed in [THIRD_PARTY_FILES.md](https://github.com/OathTech/cerberus-lean/blob/c4284b08f80c4461f97d179896868106e510327e/THIRD_PARTY_FILES.md).
  Those exceptions include other licenses for models, libc sources, web assets
  and test corpora. File-specific notices remain in place.
- **Lem / LemLib:** an external pinned dependency with its own
  [license](https://github.com/OathTech/lem-lean/blob/2d3a492758cb23dc4e417f2961983d25b36ce130/LICENSE)
  and [runtime notices](https://github.com/OathTech/lem-lean/blob/2d3a492758cb23dc4e417f2961983d25b36ce130/lean-lib/NOTICE.md).
  Its source checkout and installed binaries are not bundled here.
- **OpenSSH:** an unchanged external reference, governed by its own
  [COPYING](https://github.com/openssh/openssh-portable/blob/a8c72b842423f0774f542d3c2197247c3dd28d74/LICENCE)
  and file notices. No OpenSSH code is relicensed by this project.
- **New workbench material outside the fork:** the original workspace did not
  specify an overall license. No overall license is granted for workbench
  material without an applicable notice.
  Existing notices on copied or derived material still apply.

This public source snapshot is not presented as a uniformly BSD-licensed
distribution or a completed release.
