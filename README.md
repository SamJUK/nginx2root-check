# nginx2root-check

A bounded, accounting-only check for CVE-2026-123007 (nginx2root).

It exercises the installed nginx binary on a temporary loopback listener, stops before memory corruption, and combines that active result with the binary actually running on the host.

It does not send the test to a public endpoint, reload production nginx, crash a worker, execute a command through nginx, or include Rapid7's later amplification stages.

## Why this exists

An nginx banner is not patch evidence.

Linux distributions backport security fixes without changing the upstream version, while an upgraded package can leave old workers running until nginx is restarted.

At the other end, a remote negative result can be caused by a CDN, load balancer, disabled HTTP/2, or a response path that never reaches the accounting condition.

This checker uses three pieces of evidence:

1. The exact executable behind every running nginx process.
2. A safe active accounting sequence against that installed executable.
3. The validated configuration on disk, including whether HTTP/2 is configured.

## Run it

Requirements:

- Linux with `/proc`.
- Python 3.9 or newer.
- A running nginx installed on the host.
- Root access, so every process and executable can be inspected.

```sh
git clone https://github.com/SamJUK/nginx2root-check.git
cd nginx2root-check
sudo ./nginx2root-check \
  --acknowledge-owned-system I-AM-AUTHORIZED
```

For structured evidence:

```sh
sudo ./nginx2root-check \
  --acknowledge-owned-system I-AM-AUTHORIZED \
  --json
```

Only run it on systems you own or are explicitly authorised to test.

## Outcomes

Outcome | Exit | Meaning
--- | ---: | ---
`PATCHED` | 0 | The active sequence was rejected and every running binary maps to a supported fixed build.
`VULNERABLE` | 1 | The installed binary accepted over-credit; configuration on disk also enables HTTP/2 when that can be read.
`INCONCLUSIVE` | 2 | The active test, process mapping, configuration, or package provenance could not support a firm result.

A negative active result is never treated as sufficient patch evidence on its own.

## What happens on the host

The checker records the current nginx PID set and resolves `/proc/<pid>/exe` for every process.

It creates two deterministic files under a temporary directory: an 896-byte page and a sparse 8 MiB response body.

It starts the same installed nginx executable as an unprivileged user, with one worker and a random `127.0.0.1` port.

The accounting probe first receives exactly 65,535 ordinary HTTP/2 response bytes.
That is the positive control: a dead listener or broken fixture cannot look patched.

It then queues response DATA, cancels the owning stream, sends the bounded over-credit probes, and asks for a PING acknowledgement on the same connection.

The test stops at that accounting oracle.
It does not continue into the traffic amplification, memory corruption, crash, disclosure, or command-execution stages from the full research exploit.

Finally, it terminates only the temporary process, removes its temporary files, and verifies that the original nginx PID set did not change.

## Provenance support

The first release understands:

- Ubuntu security revisions listed in USN-9159-1.
- Packaged upstream nginx builds on Ubuntu.
- Upstream stable `1.30.7+` and mainline `1.31.9+` boundaries.

Other distributions, NGINX Plus, unmanaged binaries, containers, chroots, package-file mismatches, and replaced `(deleted)` executables fail closed as `INCONCLUSIVE`.

Ubuntu Noble `1.24.0-2ubuntu7.20` is also treated as inconclusive.
During fleet validation, byte-identical copies produced conflicting active results on different kernels, so the package label is not allowed to create a false green.

## Calibration

The same probe is tested against stock nginx controls:

- nginx 1.31.8 must report `VULNERABLE`.
- nginx 1.31.9 must report `NO_OVER_CREDIT_OBSERVED` at the probe layer.

Run the isolated Docker differential only when your container runtime is already available:

```sh
tests/docker-differential.sh
```

The script creates no published ports or host networking and removes only its own labelled containers.

## Ansible

See [docs/ansible.md](docs/ansible.md) for a fleet example that copies the repository to a temporary directory, captures JSON evidence, and fails unless the combined result is `PATCHED`.

## Safety and limitations

Read [SECURITY.md](SECURITY.md) before changing the protocol sequence or target restrictions.

This is an active diagnostic, not a general-purpose remote scanner and not an exploitability guarantee.
It validates the installed binary through a controlled cleartext HTTP/2 fixture; it does not reproduce a public TLS, CDN, proxy, or load-balancer path.

The configuration audit runs a package-verified nginx with `-T` as the stripped-down test account and reads the result from disk.
If that account cannot read or validate the configuration, the result is `INCONCLUSIVE`.
It does not claim that running workers have reloaded those settings, so HTTP/2 configured off is not reported as a proven mitigation.

## Credits

The accounting sequence is adapted from Censys Research's Apache-2.0 [`h2c_flow_control_test.py`](https://github.com/Censys-Research/nginx2root/blob/main/h2c_flow_control_test.py).

Rapid7 published the original vulnerability research and full proof of concept.
Their complete trigger intentionally continues beyond the accounting oracle and is not invoked or vendored here.

## Licence

Apache License 2.0.
