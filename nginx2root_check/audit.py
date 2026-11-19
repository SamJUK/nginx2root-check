#!/usr/bin/env python3
"""Audit the running nginx processes for CVE-2026-123007 without triggering it."""

import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path


FIXED_UBUNTU = {
    "16.04": "1.10.3-0ubuntu0.16.04.5+esm11",
    "18.04": "1.14.0-0ubuntu1.11+esm6",
    "20.04": "1.18.0-0ubuntu1.7+esm5",
    "22.04": "1.18.0-6ubuntu14.23",
    "24.04": "1.24.0-2ubuntu7.20",
    "26.04": "1.28.3-2ubuntu1.13",
    "26.10": "1.30.4-7ubuntu1.2",
}


def run(*args):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )


def read_os_release(path="/etc/os-release"):
    values = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def dpkg_at_least(installed, fixed):
    return run("dpkg", "--compare-versions", installed, "ge", fixed).returncode == 0


def upstream_fixed(version):
    parts = tuple(int(part) for part in version.split("."))
    if parts < (1, 9, 5):
        return True
    if parts >= (1, 32, 0):
        return True
    if parts >= (1, 31, 0):
        return parts >= (1, 31, 9)
    return parts >= (1, 30, 7)


def ubuntu_archive_version(version):
    match = re.fullmatch(
        r"(?P<upstream>\d+\.\d+\.\d+)-\d+ubuntu\d+(?:\.\d+)*(?:\+esm\d+)?",
        version,
    )
    return match.group("upstream") if match else None


def nginx_processes(proc_root="/proc"):
    processes = []
    errors = []
    for entry in Path(proc_root).glob("[0-9]*"):
        try:
            if (entry / "comm").read_text().strip() != "nginx":
                continue
        except FileNotFoundError:
            continue
        except OSError as error:
            if entry.exists():
                errors.append({"pid": int(entry.name), "error": str(error)})
            continue
        try:
            processes.append({
                "pid": int(entry.name),
                "exe": os.readlink(entry / "exe"),
                "mount_namespace": os.readlink(entry / "ns/mnt"),
                "host_root": os.path.samefile(entry / "root", "/"),
                "cmdline": (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                    errors="replace"
                ).strip(),
            })
        except OSError as error:
            if entry.exists():
                errors.append({"pid": int(entry.name), "error": str(error)})
    return sorted(processes, key=lambda process: process["pid"]), errors


def package_file_verified(package, executable, info_root="/var/lib/dpkg/info"):
    path = Path(executable)
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            return False
    except OSError:
        return False

    relative_path = executable.lstrip("/")
    package_names = (package, package.split(":", 1)[0])
    for package_name in dict.fromkeys(package_names):
        sums = Path(info_root) / f"{package_name}.md5sums"
        try:
            entries = sums.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for entry in entries:
            checksum, separator, entry_path = entry.partition("  ")
            if separator and entry_path == relative_path:
                digest = hashlib.md5(usedforsecurity=False)
                try:
                    with path.open("rb") as binary:
                        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                            digest.update(chunk)
                except OSError:
                    return False
                return digest.hexdigest() == checksum
    return False


def package_for(executable):
    owner = run("dpkg-query", "-S", executable)
    if owner.returncode:
        return None
    package = owner.stdout.rsplit(": ", 1)[0]
    query = run("dpkg-query", "-W", "-f=${Version}", package)
    if query.returncode:
        return None
    return {
        "name": package,
        "version": query.stdout.strip(),
        "file_verified": package_file_verified(package, executable),
    }


def package_upstream_version(package):
    match = re.match(r"^(?:\d+:)?(\d+\.\d+\.\d+)", package["version"])
    return match.group(1) if match else None


def run_unprivileged(*args):
    for name in ("nobody", "www-data", "nginx"):
        try:
            user = pwd.getpwnam(name)
            break
        except KeyError:
            continue
    else:
        raise RuntimeError("no unprivileged account is available for configuration validation")

    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        user=user.pw_uid,
        group=user.pw_gid,
        extra_groups=[],
    )


def ubuntu_package_state(package, release):
    fixed = FIXED_UBUNTU.get(release)
    if not fixed:
        return "unknown", f"Ubuntu {release or 'release'} has no recorded fixed revision"
    package_upstream = ubuntu_archive_version(package["version"])
    fixed_upstream = ubuntu_archive_version(fixed)
    if package_upstream is None or package_upstream != fixed_upstream:
        return "unknown", "package is not an Ubuntu archive build for this release series"
    if release == "24.04" and package["version"] == "1.24.0-2ubuntu7.20":
        return "unknown", "this revision produced conflicting active accounting results"
    if dpkg_at_least(package["version"], fixed):
        return "fixed", f"{package['version']} >= {fixed}"
    return "vulnerable", f"{package['version']} < {fixed}"


def inspect_binary(executable, os_release):
    package = package_for(executable)
    version = package_upstream_version(package) if package and package["file_verified"] else None
    result = {"path": executable, "package": package, "upstream_version": version}

    if package and not package["file_verified"]:
        state, reason = "unknown", "the running executable does not match package verification"
    elif package and package["name"].startswith("nginx-plus"):
        state, reason = "unknown", "NGINX Plus build provenance is not encoded"
    elif package and os_release.get("ID") == "ubuntu" and ubuntu_archive_version(package["version"]):
        state, reason = ubuntu_package_state(package, os_release.get("VERSION_ID", ""))
    elif package and os_release.get("ID") == "ubuntu" and version:
        state = "fixed" if upstream_fixed(version) else "vulnerable"
        reason = f"upstream nginx/{version}"
    else:
        state, reason = "unknown", "binary provenance and version are unknown"

    result.update(state=state, reason=reason)
    return result


def http2_enabled(config):
    active = "\n".join(
        line for line in config.splitlines() if not line.lstrip().startswith("#")
    )
    return bool(
        re.search(r"(?:^|[;{}])\s*listen\s+[^;{}]*\bhttp2\b[^;{}]*;", active)
        or re.search(r"(?:^|[;{}])\s*http2\s+on\s*;", active)
    )


def classify(processes, discovery_errors, binaries, stale, isolated, config_valid, h2_enabled):
    if discovery_errors:
        return "INCONCLUSIVE", "at least one candidate process could not be inspected"
    if not processes:
        return "INCONCLUSIVE", "no running nginx process was found"
    if stale:
        return "INCONCLUSIVE", "a running process uses a replaced binary"
    if isolated:
        return "INCONCLUSIVE", "an isolated nginx process needs image-level provenance"
    if not config_valid:
        return "INCONCLUSIVE", "the nginx configuration on disk could not be validated"
    if any(binary["state"] == "unknown" for binary in binaries):
        return "INCONCLUSIVE", "at least one running binary has unknown patch provenance"
    if all(binary["state"] == "fixed" for binary in binaries):
        return "PATCHED", "every running nginx binary contains a vendor or upstream fix"
    if not h2_enabled:
        return "INCONCLUSIVE", "configuration on disk disables HTTP/2, but live listeners were not verified"
    return "VULNERABLE", "a vulnerable running binary has HTTP/2 enabled"


def audit():
    os_release = read_os_release()
    processes, discovery_errors = nginx_processes()
    stale = [process for process in processes if process["exe"].endswith(" (deleted)")]
    host_mount_namespace = os.readlink("/proc/self/ns/mnt")
    isolated = [
        process for process in processes
        if process["mount_namespace"] != host_mount_namespace or not process["host_root"]
    ]
    executables = sorted({process["exe"].removesuffix(" (deleted)") for process in processes})
    binaries = [inspect_binary(executable, os_release) for executable in executables]

    masters = [
        process for process in processes
        if process["cmdline"].startswith("nginx: master process")
    ]
    custom_config = any(
        re.search(r"(?:^|\s)-(?:c|p)(?:\s|$)", process["cmdline"])
        for process in masters
    )
    trusted_binary = bool(
        len(binaries) == 1
        and (binaries[0].get("package") or {}).get("file_verified") is True
    )
    config = None
    if (
        len(executables) == 1
        and len(masters) == 1
        and not custom_config
        and trusted_binary
    ):
        try:
            config = run_unprivileged(executables[0], "-T")
        except (OSError, RuntimeError, subprocess.SubprocessError):
            config = None
    config_valid = bool(config and config.returncode == 0)
    config_text = (config.stdout + config.stderr) if config else ""
    h2_enabled = http2_enabled(config_text) if config_valid else None

    outcome, reason = classify(
        processes, discovery_errors, binaries, stale, isolated, config_valid, h2_enabled
    )

    return {
        "cve": "CVE-2026-123007",
        "outcome": outcome,
        "reason": reason,
        "os": {
            "id": os_release.get("ID"),
            "version": os_release.get("VERSION_ID"),
            "release": os_release.get("VERSION_CODENAME"),
        },
        "processes": processes,
        "process_discovery_errors": discovery_errors,
        "containerised_processes": [process["pid"] for process in isolated],
        "binaries": binaries,
        "nginx_config_valid": config_valid,
        "http2_enabled": h2_enabled,
    }


def main():
    print(json.dumps(audit(), sort_keys=True))


if __name__ == "__main__":
    main()
