"""
Core pipeline: orchestrates the 4-agent workflow.
Scanner → Reasoner → Fixer → Verifier
"""

import os
import json
import time
import shutil
import tempfile
import subprocess
from typing import Optional
from dataclasses import dataclass, field, asdict
from agents.scanner import ScannerAgent
from agents.reasoner import ReasonerAgent
from agents.fixer import FixerAgent
from agents.verifier import VerifierAgent


class GuardianPipeline:
    def __init__(
        self,
        api_key: str,
        verbose: bool = False,
        auto_fix: bool = True,
        submit_pr: bool = False,
    ):
        self.api_key = api_key
        self.verbose = verbose
        self.auto_fix = auto_fix
        self.submit_pr = submit_pr

    # ── Public API ────────────────────────────────────────────────────────────

    def run_from_path(self, path: str, output_path: str = "report.json") -> dict:
        return self._run(path, output_path)

    def run_from_repo(self, repo_url: str, output_path: str = "report.json") -> dict:
        tmpdir = tempfile.mkdtemp(prefix="codeguardian_")
        try:
            print(f"  📥 Cloning {repo_url}...")
            subprocess.run(
                ["git", "clone", "--depth=1", repo_url, tmpdir],
                check=True,
                capture_output=True,
            )
            return self._run(tmpdir, output_path)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Internal pipeline ─────────────────────────────────────────────────────

    def _run(self, project_path: str, output_path: str) -> dict:
        start = time.time()

        # ── Agent 1: Scan ──────────────────────────────────────────────────
        print("\n[1/4] 🔍 Scanner Agent — static analysis...")
        scanner = ScannerAgent(verbose=self.verbose)
        raw_findings = scanner.scan_directory(project_path)
        print(f"      → {len(raw_findings)} raw findings")

        if not raw_findings:
            return self._empty_result(project_path, output_path, time.time() - start)

        # ── Agent 2: Reason ────────────────────────────────────────────────
        print(f"\n[2/4] 🧠 Reasoner Agent — deep analysis ({len(raw_findings)} items)...")
        reasoner = ReasonerAgent(api_key=self.api_key, verbose=self.verbose)
        issues = reasoner.reason(raw_findings)
        real_issues = [i for i in issues if not i.false_positive]
        print(f"      → {len(real_issues)} confirmed issues ({len(issues) - len(real_issues)} false positives filtered)")

        patches = []
        verifications = []

        if self.auto_fix and real_issues:
            # ── Agent 3: Fix ───────────────────────────────────────────────
            print(f"\n[3/4] 🔧 Fixer Agent — generating patches ({len(real_issues)} issues)...")
            fixer = FixerAgent(api_key=self.api_key, verbose=self.verbose)
            patches = fixer.fix(real_issues)
            applied = sum(1 for p in patches if p.applied)
            print(f"      → {applied}/{len(patches)} patches applied")

            # ── Agent 4: Verify ────────────────────────────────────────────
            print(f"\n[4/4] ✅ Verifier Agent — validating patches...")
            verifier = VerifierAgent(
                api_key=self.api_key,
                project_root=project_path,
                verbose=self.verbose,
            )
            verifications = verifier.verify(patches)
            confirmed = sum(1 for v in verifications if v.confirmed_fixed)
            print(f"      → {confirmed}/{len(verifications)} fixes verified")
        else:
            print("\n[3/4] 🔧 Fixer Agent — skipped (--no-fix)")
            print("[4/4] ✅ Verifier Agent — skipped")

        # ── Build report ───────────────────────────────────────────────────
        duration = round(time.time() - start, 1)
        report = self._build_report(
            project_path=project_path,
            issues=issues,
            patches=patches,
            verifications=verifications,
            duration=duration,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return report

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_report(self, project_path, issues, patches, verifications, duration) -> dict:
        real = [i for i in issues if not i.false_positive]
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for i in real:
            sev = i.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        confirmed_fixed = sum(1 for v in verifications if v.confirmed_fixed)

        return {
            "scan_id": f"cg-{int(time.time())}",
            "project_path": project_path,
            "total_files_scanned": self._count_py_files(project_path),
            "vulnerabilities_found": len(real),
            "false_positives_filtered": len(issues) - len(real),
            "auto_fixed": confirmed_fixed,
            "fix_acceptance_rate": (
                f"{round(confirmed_fixed / len(real) * 100)}%"
                if real else "N/A"
            ),
            **severity_counts,
            "scan_duration_seconds": duration,
            "issues": [
                {
                    "file": i.file_path,
                    "line": i.line_number,
                    "type": i.vuln_type,
                    "severity": i.severity,
                    "cvss_score": i.cvss_score,
                    "exploitability": i.exploitability,
                    "attack_path": i.attack_path,
                    "recommendation": i.recommendation,
                    "code_snippet": i.code_snippet,
                }
                for i in real
            ],
            "patches": [
                {
                    "file": p.file_path,
                    "line": p.line_number,
                    "type": p.vuln_type,
                    "original": p.original_code,
                    "patched": p.patched_code,
                    "explanation": p.explanation,
                    "applied": p.applied,
                }
                for p in patches
            ],
        }

    def _empty_result(self, path, output_path, duration) -> dict:
        result = {
            "scan_id": f"cg-{int(time.time())}",
            "project_path": path,
            "total_files_scanned": self._count_py_files(path),
            "vulnerabilities_found": 0,
            "false_positives_filtered": 0,
            "auto_fixed": 0,
            "fix_acceptance_rate": "N/A",
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "scan_duration_seconds": round(duration, 1),
            "issues": [],
            "patches": [],
        }
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        return result

    def _count_py_files(self, root: str) -> int:
        count = 0
        for _, _, files in os.walk(root):
            count += sum(1 for f in files if f.endswith(".py"))
        return count
