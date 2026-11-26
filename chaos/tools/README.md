# The pinned validator

`validate_contract.py` is a byte-equal copy of `scripts/validate_contract.py` of the
skill `chaos-enrollment`, plugin `chaos-testing` release 0.4.0, taken from the
marketplace checkout at commit `c1231963e85f7b4601109052bc6aa7ece629b451`.
`validate_contract.py.sha256` records its SHA-256. Check the copy against the record,
then byte for byte against the installed skill; each command exits 0 only on a match:

```sh
(cd chaos/tools && sha256sum -c validate_contract.py.sha256)
cmp chaos/tools/validate_contract.py <skill-dir>/scripts/validate_contract.py
```

A new release of the skill replaces both files in one commit that names the release.
