import unittest

import triage


class RedactTests(unittest.TestCase):
    def test_password_value(self):
        out = triage.redact("connect failed password=hunter2 retry")
        self.assertNotIn("hunter2", out)
        self.assertIn(triage.REDACTED, out)

    def test_bearer_token(self):
        out = triage.redact("Authorization: Bearer abcdef1234567890xyz")
        self.assertNotIn("abcdef1234567890xyz", out)

    def test_connection_string_password(self):
        out = triage.redact("postgres://app:s3cr3tpw@db.internal:5432/app")
        self.assertNotIn("s3cr3tpw", out)
        self.assertIn("postgres://app:", out)

    def test_github_and_jwt(self):
        self.assertNotIn("ghp_abcdefghij1234567890",
                         triage.redact("tok ghp_abcdefghij1234567890 end"))
        jwt = "eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT"
        self.assertNotIn(jwt, triage.redact(f"auth {jwt} ok"))

    def test_clean_line_untouched(self):
        line = "nginx error: connect() failed (111: Connection refused)"
        self.assertEqual(triage.redact(line), line)


class SignatureTests(unittest.TestCase):
    def test_repeats_collapse(self):
        a = "2026-10-23 08:00:01 app error user 123 from 10.0.0.5 failed"
        b = "2026-10-23 09:31:44 app error user 987 from 192.168.1.9 failed"
        self.assertEqual(triage.signature(a), triage.signature(b))

    def test_seconds_and_fraction_do_not_split(self):
        a = "2026-10-23T08:00:01.123Z app error request failed"
        b = "2026-10-23T09:59:59.987Z app error request failed"
        self.assertEqual(triage.signature(a), triage.signature(b))

    def test_different_errors_differ(self):
        a = "error: disk full on /dev/sda1"
        b = "error: connection refused by upstream"
        self.assertNotEqual(triage.signature(a), triage.signature(b))


class ReportTests(unittest.TestCase):
    def test_report_has_all_sections(self):
        report = triage.build_report(hours=1)
        for heading in ("## Summary", "## 1. System", "## 2. Services",
                        "## 3. Ports", "## 4. Errors"):
            self.assertIn(heading, report)


if __name__ == "__main__":
    unittest.main()
