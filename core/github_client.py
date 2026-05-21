"""
GitHub API client for submitting patch PRs.
"""

import os
import json
import base64
from typing import List, Optional
from agents.fixer import Patch


class GitHubClient:
    """
    Wraps the GitHub REST API to create branches and submit pull requests
    with security fix patches.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GITHUB_TOKEN not set.")

    def submit_pr(self, repo: str, patches: List[Patch], base_branch: str = "main") -> Optional[str]:
        """
        Creates a branch with all applied patches and opens a PR.
        Returns the PR URL on success, None on failure.
        """
        import requests

        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

        branch_name = f"codeguardian/security-fixes-{int(__import__('time').time())}"

        # Get base SHA
        r = requests.get(
            f"{self.BASE_URL}/repos/{repo}/git/ref/heads/{base_branch}",
            headers=headers,
        )
        if r.status_code != 200:
            print(f"  ⚠️  Could not fetch base branch SHA: {r.status_code}")
            return None

        base_sha = r.json()["object"]["sha"]

        # Create new branch
        requests.post(
            f"{self.BASE_URL}/repos/{repo}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        )

        # Commit each patched file
        committed = 0
        for patch in patches:
            if not patch.applied:
                continue
            try:
                with open(patch.file_path, "rb") as f:
                    content = base64.b64encode(f.read()).decode()

                # Get current file SHA
                rel_path = os.path.relpath(patch.file_path)
                r2 = requests.get(
                    f"{self.BASE_URL}/repos/{repo}/contents/{rel_path}",
                    headers=headers,
                    params={"ref": branch_name},
                )
                file_sha = r2.json().get("sha") if r2.status_code == 200 else None

                payload = {
                    "message": f"fix({patch.vuln_type}): auto-fix at line {patch.line_number}",
                    "content": content,
                    "branch": branch_name,
                }
                if file_sha:
                    payload["sha"] = file_sha

                requests.put(
                    f"{self.BASE_URL}/repos/{repo}/contents/{rel_path}",
                    headers=headers,
                    json=payload,
                )
                committed += 1
            except Exception as e:
                print(f"  ⚠️  Failed to commit {patch.file_path}: {e}")

        if committed == 0:
            return None

        # Open PR
        pr_body = self._build_pr_body(patches)
        r3 = requests.post(
            f"{self.BASE_URL}/repos/{repo}/pulls",
            headers=headers,
            json={
                "title": f"[CodeGuardian] Security fixes — {committed} vulnerabilities patched",
                "body": pr_body,
                "head": branch_name,
                "base": base_branch,
            },
        )
        if r3.status_code == 201:
            return r3.json().get("html_url")
        return None

    def _build_pr_body(self, patches: List[Patch]) -> str:
        lines = [
            "## 🛡️ CodeGuardian Auto-Fix PR",
            "",
            "This PR was generated automatically by [CodeGuardian](https://github.com/YOUR_USERNAME/CodeGuardian).",
            "",
            "### Fixes",
            "",
        ]
        for p in patches:
            if p.applied:
                lines.append(f"- **{p.vuln_type}** @ `{p.file_path}:{p.line_number}` — {p.explanation}")
        lines += [
            "",
            "### Review Checklist",
            "- [ ] Verify each patch is contextually correct",
            "- [ ] Run full test suite",
            "- [ ] Check for edge cases",
        ]
        return "\n".join(lines)
