# Security policy

## Safe operating boundary

The supported command tests only the nginx executable already installed on the local host.

It starts a temporary unprivileged process on a random loopback port and removes it when the check finishes.

The calibration client rejects non-loopback addresses.

Do not add public-target support, crash amplification, heap manipulation, memory disclosure, command execution, persistence, or shell functionality.

The accounting probe must retain its ordinary 65,535-byte HTTP/2 positive control and must stop after the same-connection PING decision.

## Reporting a problem

Please use GitHub's private vulnerability reporting for a safety-boundary bypass or a defect that could affect the live nginx service.

For ordinary false positives, false negatives, unsupported package provenance, or compatibility problems, open an issue with:

- Distribution and release.
- Full nginx package revision.
- Kernel version.
- Python version.
- JSON output with hostnames, addresses, and paths redacted as necessary.

Do not include credentials, private keys, client names, or production addresses.
