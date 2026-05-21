"""
Agent 2: Reasoner
Uses LLM with long-chain reasoning to deeply analyze each raw finding,
assess exploitability, attack paths, and assign severity scores.
"""

import json
from typing import List
from dataclasses import dataclass
from agents.scanner import RawFinding


@dataclass
class ReasonedIssue:
    file_path: str
    line_number: int
    vuln_type: str
    code_snippet: str
    severity: str          # "critical", "high", "medium", "low"
    cvss_score: float
    exploitability: str    # "easy", "moderate", "difficult"
    attack_path: str
    recommendation: str
    reasoning_chain: str   # Full CoT reasoning from LLM
    false_positive: bool


REASONER_SYSTEM_PROMPT = """You are a senior application security engineer with 10+ years of experience.
You will be given a potential vulnerability finding from a static scanner.
Your job is to perform deep chain-of-thought reasoning to:
1. Determine if this is a real vulnerability or a false positive
2. Assess exploitability in real-world context
3. Describe the realistic attack path
4. Score severity (CVSS-style: 0.0-10.0)
5. Give a concrete fix recommendation

Think step-by-step before giving your final assessment.
Respond ONLY in valid JSON — no markdown, no preamble."""


REASONER_USER_TEMPLATE = """
Analyze this potential vulnerability:

File: {file_path}
Line: {line_number}
Type: {vuln_type}
Code: {code_snippet}
Initial Description: {description}
Scanner Confidence: {confidence}

Respond with this exact JSON structure:
{{
  "false_positive": false,
  "severity": "high",
  "cvss_score": 7.5,
  "exploitability": "moderate",
  "attack_path": "Attacker sends crafted input to endpoint X, which passes unsanitized to SQL query...",
  "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
  "reasoning_chain": "Step 1: ... Step 2: ... Step 3: ..."
}}
"""


class ReasonerAgent:
    """
    Agent 2 — LLM-powered Reasoner.
    Performs multi-step chain-of-thought analysis for each raw finding.
    """

    def __init__(self, api_key: str, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose

    def reason(self, findings: List[RawFinding]) -> List[ReasonedIssue]:
        issues = []
        total = len(findings)
        for i, finding in enumerate(findings, 1):
            if self.verbose:
                print(f"  🧠 Reasoner: Analyzing {i}/{total} — {finding.vuln_type} @ {finding.file_path}:{finding.line_number}")
            issue = self._analyze(finding)
            if issue:
                issues.append(issue)
        return issues

    def _analyze(self, finding: RawFinding) -> ReasonedIssue:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)

        prompt = REASONER_USER_TEMPLATE.format(
            file_path=finding.file_path,
            line_number=finding.line_number,
            vuln_type=finding.vuln_type,
            code_snippet=finding.code_snippet,
            description=finding.description,
            confidence=finding.confidence,
        )

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=REASONER_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        raw_text = response.content[0].text.strip()

        # Strip accidental markdown fences
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            # Fallback: treat as real, medium severity
            data = {
                "false_positive": False,
                "severity": "medium",
                "cvss_score": 5.0,
                "exploitability": "moderate",
                "attack_path": "Unable to parse reasoning.",
                "recommendation": finding.description,
                "reasoning_chain": raw_text,
            }

        return ReasonedIssue(
            file_path=finding.file_path,
            line_number=finding.line_number,
            vuln_type=finding.vuln_type,
            code_snippet=finding.code_snippet,
            severity=data.get("severity", "medium"),
            cvss_score=float(data.get("cvss_score", 5.0)),
            exploitability=data.get("exploitability", "moderate"),
            attack_path=data.get("attack_path", ""),
            recommendation=data.get("recommendation", ""),
            reasoning_chain=data.get("reasoning_chain", ""),
            false_positive=bool(data.get("false_positive", False)),
        )
