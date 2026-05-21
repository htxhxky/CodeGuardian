"""
Agent 3: Fixer
Generates context-aware, minimal patches for confirmed vulnerabilities.
"""

import json
import os
from typing import List, Optional
from dataclasses import dataclass
from agents.reasoner import ReasonedIssue


@dataclass
class Patch:
    file_path: str
    line_number: int
    vuln_type: str
    original_code: str
    patched_code: str
    explanation: str
    applied: bool = False


FIXER_SYSTEM_PROMPT = """You are a security-focused software engineer.
You will be given a confirmed vulnerability and the surrounding code context.
Generate a minimal, correct patch that:
1. Fixes the vulnerability without breaking functionality
2. Follows Python best practices
3. Is as small as possible (change only what's needed)

Respond ONLY in valid JSON — no markdown, no explanation outside JSON."""

FIXER_USER_TEMPLATE = """
Vulnerability to fix:
Type: {vuln_type}
File: {file_path}
Line: {line_number}
Severity: {severity}
Recommendation: {recommendation}

Surrounding code (lines {ctx_start}-{ctx_end}):
{context}

Respond with:
{{
  "original_line": "exact line to replace",
  "patched_line": "replacement line",
  "explanation": "one-line explanation of the fix"
}}
"""


class FixerAgent:
    """
    Agent 3 — Patch Generator.
    For each confirmed issue, reads file context and generates a minimal fix.
    """

    def __init__(self, api_key: str, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose

    def fix(self, issues: List[ReasonedIssue]) -> List[Patch]:
        patches = []
        real_issues = [i for i in issues if not i.false_positive]
        total = len(real_issues)

        for idx, issue in enumerate(real_issues, 1):
            if self.verbose:
                print(f"  🔧 Fixer: Generating patch {idx}/{total} — {issue.vuln_type}")
            patch = self._generate_patch(issue)
            if patch:
                patches.append(patch)
        return patches

    def _generate_patch(self, issue: ReasonedIssue) -> Optional[Patch]:
        import anthropic

        context, ctx_start = self._read_context(issue.file_path, issue.line_number)
        if not context:
            return None

        client = anthropic.Anthropic(api_key=self.api_key)

        prompt = FIXER_USER_TEMPLATE.format(
            vuln_type=issue.vuln_type,
            file_path=issue.file_path,
            line_number=issue.line_number,
            severity=issue.severity,
            recommendation=issue.recommendation,
            ctx_start=ctx_start,
            ctx_end=ctx_start + len(context.splitlines()) - 1,
            context=context,
        )

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            system=FIXER_SYSTEM_PROMPT,
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
            return None

        original = data.get("original_line", issue.code_snippet)
        patched = data.get("patched_line", issue.code_snippet)

        # Apply the patch in-memory
        applied = self._apply_patch(issue.file_path, original, patched)

        return Patch(
            file_path=issue.file_path,
            line_number=issue.line_number,
            vuln_type=issue.vuln_type,
            original_code=original,
            patched_code=patched,
            explanation=data.get("explanation", "Security fix applied."),
            applied=applied,
        )

    def _read_context(self, filepath: str, line_number: int, window: int = 10):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return None, 0

        start = max(0, line_number - window - 1)
        end = min(len(lines), line_number + window)
        snippet = "".join(lines[start:end])
        return snippet, start + 1

    def _apply_patch(self, filepath: str, original: str, patched: str) -> bool:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            if original.strip() not in content:
                return False

            new_content = content.replace(original.strip(), patched.strip(), 1)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)
            return True
        except OSError:
            return False
