#!/usr/bin/env python3
"""Command-line entry point for the safe nginx2root accounting check."""

import argparse
import json
import os
import sys

from .audit import audit
from .probe import installed_binary_test


ACKNOWLEDGEMENT = "I-AM-AUTHORIZED"


def combine(audit_result, probe_result):
    audit_pids = sorted(process["pid"] for process in audit_result.get("processes", []))
    probe_pids = probe_result.get("production_pids_before")
    audited_paths = sorted(binary["path"] for binary in audit_result.get("binaries", []))
    probed_path = probe_result.get("executable")

    if audit_result.get("process_discovery_errors"):
        outcome = "INCONCLUSIVE"
        reason = "at least one candidate process could not be inspected"
    elif probe_pids is not None and audit_pids != sorted(probe_pids):
        outcome = "INCONCLUSIVE"
        reason = "the production nginx PID set changed between the audit and active test"
    elif probed_path is not None and audited_paths != [probed_path]:
        outcome = "INCONCLUSIVE"
        reason = "the active test executable does not match the audited running binary"
    elif probe_result["outcome"] == "VULNERABLE":
        if audit_result["http2_enabled"] is True:
            outcome = "VULNERABLE"
            reason = "the installed binary accepted over-credit and configuration on disk enables HTTP/2"
        elif audit_result["http2_enabled"] is False:
            outcome = "INCONCLUSIVE"
            reason = "the binary is vulnerable; configuration on disk disables HTTP/2 but live listeners were not verified"
        else:
            outcome = "INCONCLUSIVE"
            reason = "the accounting bug was observed but live HTTP/2 exposure is unknown"
    elif probe_result["outcome"] == "NO_OVER_CREDIT_OBSERVED":
        if audit_result["outcome"] == "PATCHED":
            outcome = "PATCHED"
            reason = "the active sequence was rejected and every running binary maps to a fixed build"
        else:
            outcome = "INCONCLUSIVE"
            reason = "the active sequence was rejected but fixed running-binary provenance is missing"
    else:
        outcome = "INCONCLUSIVE"
        reason = probe_result["detail"]

    return {
        "schema_version": 1,
        "cve": "CVE-2026-123007",
        "outcome": outcome,
        "reason": reason,
        "audit": audit_result,
        "probe": probe_result,
    }


def exit_code(outcome):
    return {"PATCHED": 0, "VULNERABLE": 1, "INCONCLUSIVE": 2}[outcome]


def render(result):
    audit_result = result["audit"]
    probe_result = result["probe"]
    binary = audit_result["binaries"][0] if audit_result["binaries"] else {}
    package = binary.get("package") or {}

    print(f"CVE-2026-123007: {result['outcome']}")
    print(result["reason"])
    if package:
        print(f"Running package: {package.get('name')} {package.get('version')}")
    elif binary:
        print(f"Running binary: {binary.get('path')} ({binary.get('upstream_version') or 'unknown version'})")
    print(f"HTTP/2 enabled in configuration on disk: {audit_result['http2_enabled']}")
    print(f"Accounting control bytes: {probe_result.get('control_bytes', 0)}")
    print(f"Production PIDs unchanged: {probe_result.get('production_pids_unchanged', False)}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Safely exercise CVE-2026-123007 accounting in the installed nginx binary."
    )
    parser.add_argument("--json", action="store_true", help="Print structured JSON evidence")
    parser.add_argument(
        "--acknowledge-owned-system",
        required=True,
        metavar=ACKNOWLEDGEMENT,
        help="Required acknowledgement that you own or are authorised to test this host",
    )
    args = parser.parse_args(argv)
    if args.acknowledge_owned_system != ACKNOWLEDGEMENT:
        parser.error(f"--acknowledge-owned-system must be {ACKNOWLEDGEMENT}")
    return args


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() != 0:
        message = "Run as root so every nginx process and executable can be inspected"
        if args.json:
            print(json.dumps({"outcome": "INCONCLUSIVE", "reason": message}))
        else:
            print(message, file=sys.stderr)
        return 2

    try:
        result = combine(audit(), installed_binary_test())
    except Exception as error:
        message = f"checker failed closed: {error}"
        if args.json:
            print(json.dumps({"outcome": "INCONCLUSIVE", "reason": message}))
        else:
            print(message, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        render(result)
    return exit_code(result["outcome"])


if __name__ == "__main__":
    raise SystemExit(main())
