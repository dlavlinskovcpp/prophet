# One-Time Author Identity Normalization

Migration date: 2026-08-30

This metadata-only migration normalized the obsolete local-machine identity so
GitHub can attribute the active Prophet development history to the linked
account.

- Old identity: `dmitry <dmitry@dmitrys-MacBook-Air.local>`
- Canonical identity: `dmitry <doghtui@yandex.ru>`
- Old active HEAD: `1f972b142dddacacf53a82713e9888a6637e6645`
- Normalized equivalent HEAD before this documentation commit:
  `422ae58a6889619cd0a3549e52f6bf2bbe0d14b7`
- Tree SHA equality: **PASS**
- Rewritten commits: 115
- Commit messages, timestamps, trees, and parent topology: unchanged
- Protocol and file-content changes caused by rewrite: **NONE**
- Release artifact changes: **NONE**

The archival ref `archive/pre-author-normalization-20260830` and backup branch
`backup/pre-author-normalization` preserve the old active history at
`1f972b142dddacacf53a82713e9888a6637e6645`.

The immutable release tags `v1.0.0-rc4.4`, `v1.0.0-rc4.5`, and
`v1.0.0-rc4.6` were intentionally preserved on their original historical
objects and were not moved into the normalized graph. This preserves their
historical release provenance.
