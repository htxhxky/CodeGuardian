"""
Unit tests for CodeGuardian agents.
Run with: python -m pytest tests/ -v
"""

import os
import tempfile
import pytest
from agents.scanner import ScannerAgent, RawFinding


# ─── Scanner tests ────────────────────────────────────────────────────────────

class TestScannerAgent:

    def _write_tmp(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        )
        f.write(content)
        f.close()
        return f.name

    def test_detects_hardcoded_secret(self):
        code = 'password = "myS3cret!"\n'
        path = self._write_tmp(code)
        scanner = ScannerAgent()
        findings = scanner._scan_file(path)
        os.unlink(path)
        types = [f.vuln_type for f in findings]
        assert "HARDCODED_SECRET" in types

    def test_detects_sql_injection(self):
        code = 'cursor.execute("SELECT * FROM u WHERE name = \'%s\'" % name)\n'
        path = self._write_tmp(code)
        scanner = ScannerAgent()
        findings = scanner._scan_file(path)
        os.unlink(path)
        types = [f.vuln_type for f in findings]
        assert "SQL_INJECTION" in types

    def test_detects_command_injection(self):
        code = "import os\nresult = os.system(cmd)\n"
        path = self._write_tmp(code)
        scanner = ScannerAgent()
        findings = scanner._scan_file(path)
        os.unlink(path)
        types = [f.vuln_type for f in findings]
        assert "COMMAND_INJECTION" in types

    def test_detects_pickle(self):
        code = "import pickle\nobj = pickle.loads(data)\n"
        path = self._write_tmp(code)
        scanner = ScannerAgent()
        findings = scanner._scan_file(path)
        os.unlink(path)
        types = [f.vuln_type for f in findings]
        assert "PICKLE_DESERIALIZE" in types

    def test_detects_weak_hash(self):
        code = "import hashlib\nhashlib.md5(pw.encode()).hexdigest()\n"
        path = self._write_tmp(code)
        scanner = ScannerAgent()
        findings = scanner._scan_file(path)
        os.unlink(path)
        types = [f.vuln_type for f in findings]
        assert "WEAK_HASH" in types

    def test_clean_file_no_findings(self):
        code = (
            "import secrets\n"
            "token = secrets.token_hex(32)\n"
            "import hmac\nhmac.compare_digest(a, b)\n"
        )
        path = self._write_tmp(code)
        scanner = ScannerAgent()
        findings = scanner._scan_file(path)
        os.unlink(path)
        # Should not flag clean code
        dangerous = [f for f in findings if f.vuln_type in (
            "HARDCODED_SECRET", "SQL_INJECTION", "COMMAND_INJECTION"
        )]
        assert len(dangerous) == 0

    def test_scan_directory(self):
        tmpdir = tempfile.mkdtemp()
        vuln_path = os.path.join(tmpdir, "app.py")
        with open(vuln_path, "w") as f:
            f.write('api_key = "secret123"\nos.system(cmd)\n')

        scanner = ScannerAgent()
        findings = scanner.scan_directory(tmpdir)
        assert len(findings) >= 2

        import shutil
        shutil.rmtree(tmpdir)

    def test_finding_has_required_fields(self):
        code = 'secret = "abc123xyz"\n'
        path = self._write_tmp(code)
        scanner = ScannerAgent()
        findings = scanner._scan_file(path)
        os.unlink(path)
        assert len(findings) > 0
        f = findings[0]
        assert f.file_path
        assert f.line_number > 0
        assert f.vuln_type
        assert f.code_snippet
        assert f.confidence in ("high", "medium", "low")
