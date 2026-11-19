import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from nginx2root_check import audit, probe
from nginx2root_check.cli import combine, exit_code, main, parse_args


class CheckerTests(unittest.TestCase):
    def test_upstream_boundaries_have_positive_and_negative_controls(self):
        self.assertFalse(audit.upstream_fixed("1.31.8"))
        self.assertTrue(audit.upstream_fixed("1.31.9"))
        self.assertFalse(audit.upstream_fixed("1.30.6"))
        self.assertTrue(audit.upstream_fixed("1.30.7"))

    @patch.object(audit, "dpkg_at_least", return_value=True)
    def test_fixed_ubuntu_control(self, _compare):
        state, _reason = audit.ubuntu_package_state(
            {"name": "nginx", "version": "1.18.0-6ubuntu14.23"}, "22.04"
        )
        self.assertEqual(state, "fixed")

    @patch.object(audit, "dpkg_at_least", return_value=False)
    def test_vulnerable_ubuntu_control(self, _compare):
        state, _reason = audit.ubuntu_package_state(
            {"name": "nginx", "version": "1.18.0-6ubuntu14.22"}, "22.04"
        )
        self.assertEqual(state, "vulnerable")

    def test_conflicting_noble_revision_fails_closed(self):
        state, _reason = audit.ubuntu_package_state(
            {"name": "nginx", "version": "1.24.0-2ubuntu7.20"}, "24.04"
        )
        self.assertEqual(state, "unknown")

    def test_third_party_ubuntu_named_package_is_not_a_vendor_backport(self):
        state, _reason = audit.ubuntu_package_state(
            {
                "name": "nginx",
                "version": "1.30.0-1+ubuntu24.04.1+deb.sury.org+1",
            },
            "24.04",
        )
        self.assertEqual(state, "unknown")

    def test_package_file_verification_has_matching_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "usr/sbin/nginx"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"known nginx bytes")
            info_root = root / "var/lib/dpkg/info"
            info_root.mkdir(parents=True)
            relative = str(executable).lstrip("/")
            checksum = hashlib.md5(
                executable.read_bytes(), usedforsecurity=False
            ).hexdigest()
            sums = info_root / "nginx.md5sums"
            sums.write_text(f"{checksum}  {relative}\n")

            self.assertTrue(
                audit.package_file_verified("nginx", str(executable), info_root)
            )
            executable.write_bytes(b"locally replaced bytes")
            self.assertFalse(
                audit.package_file_verified("nginx", str(executable), info_root)
            )

    def test_package_file_without_checksum_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "nginx"
            executable.write_bytes(b"unlisted")
            self.assertFalse(
                audit.package_file_verified("nginx", str(executable), tmp)
            )

    def test_process_discovery_error_fails_closed(self):
        outcome, _reason = audit.classify(
            [],
            [{"pid": 123, "error": "permission denied"}],
            [],
            [],
            [],
            False,
            None,
        )
        self.assertEqual(outcome, "INCONCLUSIVE")

    def test_package_upstream_version_handles_epoch(self):
        self.assertEqual(
            audit.package_upstream_version(
                {"version": "1:1.31.9-1~ubuntu24.04.1"}
            ),
            "1.31.9",
        )

    @patch.object(audit.subprocess, "run")
    @patch.object(audit.pwd, "getpwnam")
    def test_configuration_validation_drops_privileges(self, getpwnam, run):
        getpwnam.return_value = SimpleNamespace(pw_uid=65534, pw_gid=65534)
        audit.run_unprivileged("/usr/sbin/nginx", "-T")
        run.assert_called_once()
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["user"], 65534)
        self.assertEqual(kwargs["group"], 65534)
        self.assertEqual(kwargs["extra_groups"], [])

    @patch.object(audit, "package_for")
    def test_unverified_package_never_supplies_an_upstream_version(self, package_for):
        package_for.return_value = {
            "name": "nginx",
            "version": "1.31.9-1",
            "file_verified": False,
        }
        result = audit.inspect_binary("/tmp/untrusted-nginx", {"ID": "ubuntu"})
        self.assertIsNone(result["upstream_version"])
        self.assertEqual(result["state"], "unknown")

    def test_http2_detection_handles_inline_and_multiline_directives(self):
        self.assertTrue(audit.http2_enabled("server { listen 443 ssl http2; }"))
        self.assertTrue(audit.http2_enabled("server {\n listen 443\n ssl\n http2;\n}"))
        self.assertTrue(audit.http2_enabled("server { http2 on; }"))
        self.assertFalse(audit.http2_enabled("server { listen 443 ssl; http2 off; }"))

    def test_frame_round_trip(self):
        encoded = probe.frame(probe.PING, 0, 0, b"POC-SYNC")
        buffer = bytearray()
        self.assertEqual(
            probe.decode_frames(buffer, encoded),
            [(probe.PING, 0, 0, b"POC-SYNC")],
        )
        self.assertEqual(buffer, b"")

    def test_ping_ack_requires_matching_ack(self):
        self.assertTrue(
            probe.has_ping_ack([(probe.PING, probe.ACK, 0, b"POC-SYNC")])
        )
        self.assertFalse(probe.has_ping_ack([(probe.PING, 0, 0, b"POC-SYNC")]))

    def test_flow_control_goaway_requires_error_code_three(self):
        flow_control = b"\0" * 4 + (3).to_bytes(4, "big")
        internal_error = b"\0" * 4 + (2).to_bytes(4, "big")
        self.assertTrue(
            probe.has_flow_control_goaway([(probe.GOAWAY, 0, 0, flow_control)])
        )
        self.assertFalse(
            probe.has_flow_control_goaway([(probe.GOAWAY, 0, 0, internal_error)])
        )

    def test_positive_oracle_wins_over_fixed_label(self):
        result = combine(
            {"outcome": "PATCHED", "http2_enabled": True},
            {"outcome": "VULNERABLE", "detail": "accepted"},
        )
        self.assertEqual(result["outcome"], "VULNERABLE")
        self.assertEqual(exit_code(result["outcome"]), 1)

    def test_negative_probe_needs_fixed_provenance(self):
        result = combine(
            {"outcome": "INCONCLUSIVE", "http2_enabled": True},
            {"outcome": "NO_OVER_CREDIT_OBSERVED", "detail": "rejected"},
        )
        self.assertEqual(result["outcome"], "INCONCLUSIVE")

    def test_negative_probe_with_fixed_provenance_is_patched(self):
        result = combine(
            {"outcome": "PATCHED", "http2_enabled": True},
            {"outcome": "NO_OVER_CREDIT_OBSERVED", "detail": "rejected"},
        )
        self.assertEqual(result["outcome"], "PATCHED")
        self.assertEqual(exit_code(result["outcome"]), 0)

    def test_vulnerable_binary_with_http2_disabled_is_inconclusive(self):
        result = combine(
            {"outcome": "INCONCLUSIVE", "http2_enabled": False},
            {"outcome": "VULNERABLE", "detail": "accepted"},
        )
        self.assertEqual(result["outcome"], "INCONCLUSIVE")
        self.assertEqual(exit_code(result["outcome"]), 2)

    def test_pid_change_between_audit_and_probe_is_inconclusive(self):
        result = combine(
            {
                "outcome": "PATCHED",
                "http2_enabled": True,
                "processes": [{"pid": 10}],
            },
            {
                "outcome": "NO_OVER_CREDIT_OBSERVED",
                "detail": "rejected",
                "production_pids_before": [11],
            },
        )
        self.assertEqual(result["outcome"], "INCONCLUSIVE")

    def test_probed_executable_must_match_audited_binary(self):
        result = combine(
            {
                "outcome": "PATCHED",
                "http2_enabled": True,
                "binaries": [{"path": "/usr/sbin/nginx"}],
            },
            {
                "outcome": "NO_OVER_CREDIT_OBSERVED",
                "detail": "rejected",
                "executable": "/opt/nginx/sbin/nginx",
            },
        )
        self.assertEqual(result["outcome"], "INCONCLUSIVE")

    def test_acknowledgement_is_exact(self):
        args = parse_args(
            ["--acknowledge-owned-system", "I-AM-AUTHORIZED", "--json"]
        )
        self.assertTrue(args.json)

        with self.assertRaises(SystemExit):
            parse_args(["--acknowledge-owned-system", "yes"])

    @patch("nginx2root_check.cli.os.geteuid", return_value=1000)
    def test_non_root_fails_inconclusive(self, _geteuid):
        self.assertEqual(
            main(["--acknowledge-owned-system", "I-AM-AUTHORIZED", "--json"]),
            2,
        )

    @patch("nginx2root_check.cli.os.geteuid", return_value=0)
    @patch("nginx2root_check.cli.audit", side_effect=OSError("unreadable proc"))
    def test_unhandled_audit_error_fails_inconclusive(self, _audit, _geteuid):
        self.assertEqual(
            main(["--acknowledge-owned-system", "I-AM-AUTHORIZED", "--json"]),
            2,
        )


if __name__ == "__main__":
    unittest.main()
