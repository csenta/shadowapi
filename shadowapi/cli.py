"""
Unified Command-Line Interface for ShadowAPI.
"""

import argparse
import json
import sys

from shadowapi.core.har_parser import HARParser
from shadowapi.core.spec_builder import SpecBuilder
from shadowapi.engine.drift_detector import DriftDetector
from shadowapi.engine.reporter import ReportGenerator


def handle_synthesize(args: argparse.Namespace) -> int:
    try:
        transactions = HARParser.parse_file(args.traffic)
    except Exception as e:
        print(f"[ERROR] Failed to parse traffic file {args.traffic}: {e}")
        return 1

    print(f"📦 Parsed {len(transactions)} HTTP transactions from {args.traffic}")
    builder = SpecBuilder(title=args.title, version=args.version)
    signatures = builder.build_signatures(transactions)
    spec = builder.synthesize_openapi(signatures)

    out_format = "yaml" if args.output.endswith((".yaml", ".yml")) else "json"
    if out_format == "yaml":
        spec_text = builder.export_yaml(spec)
    else:
        spec_text = builder.export_json(spec)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(spec_text)
        print(f"✅ Synthesized OpenAPI 3.1 specification saved to {args.output} ({len(signatures)} unique endpoints)")
    else:
        print(spec_text)

    return 0


def handle_diff(args: argparse.Namespace) -> int:
    try:
        transactions = HARParser.parse_file(args.traffic)
    except Exception as e:
        print(f"[ERROR] Failed to parse traffic file {args.traffic}: {e}")
        return 1

    try:
        detector = DriftDetector.from_file(args.spec)
    except Exception as e:
        print(f"[ERROR] Failed to load declared OpenAPI spec {args.spec}: {e}")
        return 1

    builder = SpecBuilder()
    signatures = builder.build_signatures(transactions)
    report = detector.analyze(signatures, transactions)

    # 1. Terminal Output
    ReportGenerator.print_terminal_summary(report)

    # 2. JSON Export
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"📄 JSON report saved to {args.output_json}")

    # 3. HTML Export
    if args.output_html:
        html = ReportGenerator.generate_html_report(report)
        with open(args.output_html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"📊 Interactive HTML report saved to {args.output_html}")

    if args.fail_on_risk and report.risk_score >= args.fail_on_risk:
        print(f"❌ CI Gate Failed: Risk score {report.risk_score} exceeds threshold {args.fail_on_risk}!")
        return 2

    return 0


def handle_scan(args: argparse.Namespace) -> int:
    """Convenience alias for diff/audit."""
    return handle_diff(args)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="shadowapi",
        description="ShadowAPI: Autonomous API Drift & Zombie Endpoint Discovery Engine",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Synthesize
    p_synth = subparsers.add_parser("synthesize", help="Synthesize OpenAPI 3.1 spec from observed traffic/HAR")
    p_synth.add_argument("--traffic", required=True, help="Path to HAR or JSON traffic log file")
    p_synth.add_argument("--output", required=True, help="Output file path (.json or .yaml)")
    p_synth.add_argument("--title", default="Synthesized Runtime API", help="OpenAPI title")
    p_synth.add_argument("--version", default="1.0.0", help="OpenAPI version")

    # Diff
    p_diff = subparsers.add_parser("diff", help="Diff observed traffic against declared ground-truth OpenAPI spec")
    p_diff.add_argument("--traffic", required=True, help="Path to HAR or JSON traffic log file")
    p_diff.add_argument("--spec", required=True, help="Path to declared OpenAPI spec (.json or .yaml)")
    p_diff.add_argument("--output-json", default="", help="Path to save JSON report")
    p_diff.add_argument("--output-html", default="", help="Path to save interactive HTML report")
    p_diff.add_argument("--fail-on-risk", type=int, default=0, help="Fail with exit code 2 if risk >= threshold")

    # Scan (alias)
    p_scan = subparsers.add_parser("scan", help="Scan API traffic against specification with CI gate")
    p_scan.add_argument("--traffic", required=True, help="Path to HAR or JSON traffic log file")
    p_scan.add_argument("--spec", required=True, help="Path to declared OpenAPI spec (.json or .yaml)")
    p_scan.add_argument("--output-json", default="", help="Path to save JSON report")
    p_scan.add_argument("--output-html", default="", help="Path to save interactive HTML report")
    p_scan.add_argument("--fail-on-risk", type=int, default=50, help="Fail with exit code 2 if risk >= threshold")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "synthesize":
        return handle_synthesize(args)
    elif args.command == "diff":
        return handle_diff(args)
    elif args.command == "scan":
        return handle_scan(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
