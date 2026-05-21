"""
Agent 1: Scanner
Performs static analysis to detect potential vulnerabilities in Python code.
"""

import ast
import re
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RawFinding:
    file_path: str
    line_number: int
    vuln_type: str
    code_snippet: str
    description: str
    confidence: str  # "high", "medium", "low"


# ─── Rule-based pattern detectors ────────────────────────────────────────────

REGEX_RULES = [
    {
        "id": "HARDCODED_SECRET",
        "pattern": re.compile(
            r'(password|secret|api_key|token|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']',
            re.IGNORECASE,
        ),
        "description": "Hardcoded credential or secret detected.",
        "confidence": "high",
    },
    {
        "id": "SQL_INJECTION",
        "pattern": re.compile(
            r'(execute|cursor\.execute)\s*\(\s*["\'].*%[s|d].*["\'].*%',
            re.IGNORECASE,
        ),
        "description": "Possible SQL injection via string formatting.",
        "confidence": "high",
    },
    {
        "id": "COMMAND_INJECTION",
        "pattern": re.compile(
            r'(os\.system|subprocess\.call|subprocess\.run|eval|exec)\s*\(',
            re.IGNORECASE,
        ),
        "description": "Dangerous function call that may allow command injection.",
        "confidence": "medium",
    },
    {
        "id": "DEBUG_MODE",
        "pattern": re.compile(r'(app\.run|DEBUG)\s*=?\s*True', re.IGNORECASE),
        "description": "Debug mode enabled — must be disabled in production.",
        "confidence": "medium",
    },
    {
        "id": "INSECURE_RANDOM",
        "pattern": re.compile(r'random\.(random|randint|choice)\(', re.IGNORECASE),
        "description": "Insecure random number generator used for security-sensitive context.",
        "confidence": "low",
    },
    {
        "id": "XSS_FLASK",
        "pattern": re.compile(r'return\s+.*request\.(args|form|values)', re.IGNORECASE),
        "description": "User input returned directly — possible XSS vulnerability.",
        "confidence": "medium",
    },
    {
        "id": "OPEN_REDIRECT",
        "pattern": re.compile(r'redirect\s*\(\s*request\.(args|form)', re.IGNORECASE),
        "description": "Open redirect using unvalidated user input.",
        "confidence": "high",
    },
    {
        "id": "PICKLE_DESERIALIZE",
        "pattern": re.compile(r'pickle\.loads?\(', re.IGNORECASE),
        "description": "Unsafe deserialization with pickle — can lead to RCE.",
        "confidence": "high",
    },
    {
        "id": "YAML_LOAD",
        "pattern": re.compile(r'yaml\.load\s*\((?!.*Loader)', re.IGNORECASE),
        "description": "yaml.load() without Loader is unsafe; use yaml.safe_load().",
        "confidence": "high",
    },
    {
        "id": "WEAK_HASH",
        "pattern": re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE),
        "description": "Weak hashing algorithm (MD5/SHA1) used.",
        "confidence": "medium",
    },
]


class ScannerAgent:
    """
    Agent 1 — Static Scanner.
    Walks the target codebase and applies regex + AST-based rules
    to identify potential security vulnerabilities.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def scan_directory(self, path: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        py_files = self._collect_python_files(path)

        if self.verbose:
            print(f"  🔍 Scanner: Found {len(py_files)} Python files to scan")

        for fpath in py_files:
            findings.extend(self._scan_file(fpath))

        if self.verbose:
            print(f"  🔍 Scanner: {len(findings)} raw findings")

        return findings

    def _collect_python_files(self, root: str) -> List[str]:
        result = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip hidden dirs, venv, __pycache__
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".") and d not in ("venv", "__pycache__", "node_modules", ".git")
            ]
            for fname in filenames:
                if fname.endswith(".py"):
                    result.append(os.path.join(dirpath, fname))
        return result

    def _scan_file(self, filepath: str) -> List[RawFinding]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return findings

        for line_no, line in enumerate(lines, start=1):
            for rule in REGEX_RULES:
                if rule["pattern"].search(line):
                    findings.append(
                        RawFinding(
                            file_path=filepath,
                            line_number=line_no,
                            vuln_type=rule["id"],
                            code_snippet=line.rstrip(),
                            description=rule["description"],
                            confidence=rule["confidence"],
                        )
                    )

        # AST-based checks
        findings.extend(self._ast_checks(filepath, lines))
        return findings

    def _ast_checks(self, filepath: str, lines: List[str]) -> List[RawFinding]:
        """Additional AST-level checks."""
        findings = []
        source = "".join(lines)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Detect assert statements used for auth (stripped in optimized mode)
            if isinstance(node, ast.Assert):
                snippet = lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else ""
                if any(kw in snippet.lower() for kw in ("auth", "permission", "admin", "role")):
                    findings.append(
                        RawFinding(
                            file_path=filepath,
                            line_number=node.lineno,
                            vuln_type="ASSERT_AUTH",
                            code_snippet=snippet,
                            description="assert used for auth check — stripped in Python -O mode.",
                            confidence="high",
                        )
                    )

            # Detect __eq__ on sensitive objects (timing attack)
            if isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.Eq):
                snippet = lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else ""
                if any(kw in snippet.lower() for kw in ("token", "password", "secret", "hash")):
                    findings.append(
                        RawFinding(
                            file_path=filepath,
                            line_number=node.lineno,
                            vuln_type="TIMING_ATTACK",
                            code_snippet=snippet,
                            description="Direct equality check on secret — use hmac.compare_digest().",
                            confidence="medium",
                        )
                    )

        return findings
