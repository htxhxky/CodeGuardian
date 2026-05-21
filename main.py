#!/usr/bin/env python3
"""
CodeGuardian - Multi-Agent Code Security Audit & Auto-Fix System
Entry point for CLI usage.
"""

import argparse
import sys
import os
from core.pipeline import GuardianPipeline


def parse_args():
    parser = argparse.ArgumentParser(
        description="CodeGuardian: AI-powered multi-agent security auditing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --path ./my_project
  python main.py --repo https://github.com/user/repo
  python main.py --path ./my_project --output report.json --no-fix
        """
    )
    parser.add_argument("--path", type=str, help="Local path to scan")
    parser.add_argument("--repo", type=str, help="GitHub repo URL to clone and scan")
    parser.add_argument("--output", type=str, default="codeguardian_report.json",
                        help="Output report file (default: codeguardian_report.json)")
    parser.add_argument("--no-fix", action="store_true",
                        help="Scan only, skip auto-fix")
    parser.add_argument("--no-pr", action="store_true",
                        help="Generate patches locally, don't submit PR")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.path and not args.repo:
        print("❌ Error: Please provide --path or --repo")
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("❌ Error: ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)

    print("🛡️  CodeGuardian starting...")
    print("=" * 50)

    pipeline = GuardianPipeline(
        api_key=api_key,
        verbose=args.verbose,
        auto_fix=not args.no_fix,
        submit_pr=not args.no_pr,
    )

    if args.repo:
        result = pipeline.run_from_repo(args.repo, output_path=args.output)
    else:
        result = pipeline.run_from_path(args.path, output_path=args.output)

    print("\n" + "=" * 50)
    print(f"✅ Scan complete. Report saved to: {args.output}")
    print(f"   Found:    {result['vulnerabilities_found']} vulnerabilities")
    print(f"   Fixed:    {result['auto_fixed']} auto-fixed")
    print(f"   Critical: {result['critical']}")
    print(f"   High:     {result['high']}")
    print(f"   Duration: {result['scan_duration_seconds']}s")


if __name__ == "__main__":
    main()
