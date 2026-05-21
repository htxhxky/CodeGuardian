"""
Agent 4: Verifier
Validates that applied patches don't break tests, and closes the feedback loop.
"""

import subprocess
import os
import json
from typing import List
from dataclasses import dataclass
from agents.fixer import Patch


@dataclass
class VerificationResult:
    patch: Patch
    tests_passed: bool
    test_output: str
    confirmed_fixed: bool
    needs_rework: bool
    rework_reason: str


VERIFIER_SYSTEM_PROMPT = """You are a code review AI.
Given an original vulnerability, the applied patch, and test results,
determine if the fix is correct, complete, and doesn't introduce new issues.
Respond ONLY in valid JSON."""

VERIFIER_USER_TEMPLATE = """
Original vulnerability: {vuln_type}
Original code: {original}
Patched code:  {patched}
Patch explanation: {explanation}
Test results: {test_results}

Assess the patch:
{{
  "confirmed_fixed": true,
  "needs_rework": false,
  "rework_reason": ""
}}
"""


class VerifierAgent:
    """
    Agent 4 — Verifier.
    Runs the test suite after patching and uses LLM judgment to
    confirm whether each fix is valid.
    """

    def __init__(self, api_key: str, project_root: str, verbose: bool = False):
        self.api_key = api_key
        self.project_root = project_root
        self.verbose = verbose

    def verify(self, patches: List[Patch]) -> List[VerificationResult]:
        results = []
        test_output = self._run_tests()

        for patch in patches:
            if self.verbose:
                print(f"  ✅ Verifier: Checking patch — {patch.vuln_type} @ {patch.file_path}:{patch.line_number}")
            result = self._verify_patch(patch, test_output)
            results.append(result)

        return results

    def _run_tests(self) -> str:
        """Run pytest in the project root and capture output."""
        try:
            proc = subprocess.run(
                ["python", "-m", "pytest", "--tb=short", "-q"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = proc.stdout + proc.stderr
            return output[:3000]  # Truncate for LLM context
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Tests could not be run (pytest not found or timed out)."

    def _verify_patch(self, patch: Patch, test_output: str) -> VerificationResult:
        import anthropic

        tests_passed = (
            "failed" not in test_output.lower()
            and "error" not in test_output.lower()
        )

        if not patch.applied:
            return VerificationResult(
                patch=patch,
                tests_passed=tests_passed,
                test_output=test_output,
                confirmed_fixed=False,
                needs_rework=True,
                rework_reason="Patch could not be applied to source file.",
            )

        client = anthropic.Anthropic(api_key=self.api_key)

        prompt = VERIFIER_USER_TEMPLATE.format(
            vuln_type=patch.vuln_type,
            original=patch.original_code,
            patched=patch.patched_code,
            explanation=patch.explanation,
            test_results=test_output,
        )

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=256,
            system=VERIFIER_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"confirmed_fixed": tests_passed, "needs_rework": not tests_passed, "rework_reason": ""}

        return VerificationResult(
            patch=patch,
            tests_passed=tests_passed,
            test_output=test_output,
            confirmed_fixed=bool(data.get("confirmed_fixed", tests_passed)),
            needs_rework=bool(data.get("needs_rework", False)),
            rework_reason=data.get("rework_reason", ""),
        )
