#!/usr/bin/env python3
"""
PhishWatch CLI
Command-line interface for the PhishWatch platform.
"""

import argparse
import json
import logging
import sys

from phishwatch import __version__


def main():
    parser = argparse.ArgumentParser(
        prog="phishwatch",
        description="PhishWatch — Real-time Phishing Detection Platform",
    )
    parser.add_argument("-V", "--version", action="version", version=f"PhishWatch {__version__}")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── serve ──
    serve_p = sub.add_parser("serve", help="Start the web dashboard")
    serve_p.add_argument("-H", "--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    serve_p.add_argument("-p", "--port", type=int, default=5000, help="Port (default: 5000)")
    serve_p.add_argument("--debug", action="store_true", help="Debug mode")

    # ── analyze ──
    analyze_p = sub.add_parser("analyze", help="Analyze a single domain")
    analyze_p.add_argument("domain", help="Domain to analyze")
    analyze_p.add_argument("--json", action="store_true", dest="as_json", help="JSON output")

    # ── scan ──
    scan_p = sub.add_parser("scan", help="Run OpenSquat scan with keywords")
    scan_p.add_argument("-k", "--keywords", nargs="+", required=True, help="Keywords to scan")

    args = parser.parse_args()

    if args.command == "serve":
        from phishwatch.app import PhishWatch as PW
        pw = PW()
        pw.run(host=args.host, port=args.port, debug=args.debug)

    elif args.command == "analyze":
        from phishwatch.core.domain_analyzer import DomainAnalyzer
        from phishwatch.core.threat_classifier import ThreatClassifier
        from phishwatch.core.ics_iot_detector import ICSIoTDetector

        analyzer = DomainAnalyzer()
        classifier = ThreatClassifier()
        ics = ICSIoTDetector()

        analysis = analyzer.analyze(args.domain)
        ics_det = ics.analyze(args.domain)
        score = classifier.calculate_risk(args.domain, analysis, ics_det)
        report = classifier.report(args.domain, analysis, score, ics_det)

        if args.as_json:
            print(json.dumps(report, indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"  PhishWatch Domain Analysis")
            print(f"{'='*60}")
            print(f"  Domain:       {args.domain}")
            print(f"  Risk Score:   {score}/100")
            print(f"  Threat Level: {report['threat_level']}")
            print(f"  Summary:      {report['summary']}")
            if report.get("ics_context"):
                ctx = report["ics_context"]
                print(f"\n  [ICS/OT Context]")
                print(f"  Category:     {ctx.get('category', 'N/A')}")
                print(f"  Sector:       {ctx.get('sector', 'N/A')}")
                print(f"  Vendors:      {', '.join(ctx.get('vendors', [])) or 'None'}")
                print(f"  Protocols:    {', '.join(ctx.get('protocols', [])) or 'None'}")
                print(f"  MITRE ICS:    {', '.join(ctx.get('mitre_techniques', [])) or 'None'}")
                print(f"  Confidence:   {ctx.get('confidence', 0):.0%}")
            print(f"\n  Recommendations:")
            for r in report.get("recommendations", []):
                print(f"    • {r}")
            print(f"{'='*60}\n")

    elif args.command == "scan":
        from phishwatch.core.opensquat_integration import OpenSquatIntegration
        osq = OpenSquatIntegration(keywords=args.keywords)
        results = osq.scan(args.keywords)
        if results:
            print(json.dumps(results, indent=2))
        else:
            print("No results (OpenSquat may not be installed)")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
