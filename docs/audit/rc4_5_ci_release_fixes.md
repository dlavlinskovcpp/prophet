# RC4.5 CI release fixes

RC4.5 contains only release-engineering corrections required to make the
existing RC4.4 acceptance gates execute on their intended CI environments:

- the deterministic signer deployment fixture uses a platform-stable path;
- the attester CI job installs the pinned local validator toolchain and builds
  the localtest program required by its existing acceptance test;
- the Anchor CI job checks the P0C4 recovery-retirement guard instead of
  invoking the retired pre-P0C4 Vault smoke entrypoint; and
- both production runtime images install the reviewed fixed SQLite runtime
  package required by the current vulnerability policy.

The revision-4 acceptance basis remains semantically valid and unchanged. It
binds the RC4.4 protocol, topology, signer-boundary, and cryptographic
acceptance evidence; CI image identity and vulnerability inventory are
independent release gates and are not inputs to that manifest. The revision-4
manifest and its SHA256 are therefore not regenerated for RC4.5.
