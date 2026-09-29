# Security policy

BareRelic parses untrusted, possibly adversarial disk images and is often
run with elevated privileges. Bugs that let crafted media cause any of the
following are security issues:

- writing outside the case directory (path traversal, symlink tricks);
- writing to the source device or image;
- unbounded memory, CPU or disk consumption;
- crashes (panics) while parsing;
- silently wrong provenance (extents, hashes or journal entries that do not
  match what was written).

## Reporting

Please report vulnerabilities privately through GitHub's
**Security → Report a vulnerability** on
<https://github.com/shanurwan/BareRelic>, not in public issues. Include the
command line, the tool version (`barerelic version --json`) and, if
possible, a minimal image that reproduces the problem. Do not attach real
evidence or personal data.

## Hardening in place

See [docs/forensic-principles.md](docs/forensic-principles.md#threat-model).
Every parser has a Go fuzz target (`make fuzz`); crashers are kept under
`testdata/fuzz` as permanent regression tests.
