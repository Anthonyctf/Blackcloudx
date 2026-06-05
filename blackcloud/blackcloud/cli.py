#!/usr/bin/env python3
"""BlackCloud - Command Line Interface"""

import argparse
import asyncio
import json
import sys
import os
from typing import List, Optional

from .models import ScanConfig
from .scanner import CloudBucketScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackcloud",
        description="Expert-Tier Multi-Cloud Storage Bucket Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  blackcloud -d example.com
  blackcloud -d example.com -p aws gcp --all-regions
  blackcloud -d example.com -k AKIA... SECRET... --stealth
  blackcloud -d example.com -o results.json --workers 100
        """,
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain or bucket name")
    parser.add_argument("-p", "--providers", nargs="+", default=["aws", "gcp", "azure"],
                        choices=["aws", "gcp", "azure", "s3", "gcs", "blob"],
                        help="Cloud providers to scan")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Max concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--all-regions", action="store_true", help="Scan all 32 AWS regions")
    parser.add_argument("--no-permutations", action="store_true", help="Disable naming permutations")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (slower, randomized)")
    parser.add_argument("--no-content-analysis", action="store_true", help="Skip content/PII analysis")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS CNAME lookups")
    parser.add_argument("--no-policy", action="store_true", help="Skip policy/ACL enumeration")
    parser.add_argument("--no-presigned", action="store_true", help="Skip presigned URL tests")
    parser.add_argument("--no-takeover", action="store_true", help="Skip takeover detection")
    parser.add_argument("--no-entropy", action="store_true", help="Skip entropy analysis")
    parser.add_argument("--no-rate-limit", action="store_true", help="Disable adaptive rate limiting")
    parser.add_argument("-k", "--aws-keys", nargs=2, metavar=("ACCESS_KEY", "SECRET_KEY"),
                        help="AWS credentials for authenticated tests")
    parser.add_argument("--gcp-token", help="GCP OAuth token for authenticated tests")
    parser.add_argument("--azure-sas", help="Azure SAS token for authenticated tests")
    parser.add_argument("--proxy", help="HTTP proxy (http://host:port)")
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    parser.add_argument("--wordlist", help="Custom wordlist file for permutations")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    return parser


def load_wordlist(path: str) -> List[str]:
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def print_result(result, verbose: bool = False):
    risk_colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "MEDIUM": "\033[94m",
        "LOW": "\033[92m",
        "INFO": "\033[90m",
    }
    reset = "\033[0m"
    color = risk_colors.get(result.exposure, "")
    print(f"{color}[{result.exposure}]{reset} {result.provider.upper()} {result.bucket} -> {result.url} (HTTP {result.status})")
    if result.keys_count > 0:
        print(f"      Keys: {result.keys_count}")
    if result.sensitive_keys:
        print(f"      Sensitive: {', '.join(result.sensitive_keys[:5])}")
    if result.pii_findings:
        for k, v in result.pii_findings.items():
            print(f"      PII[{k}]: {len(v)} matches")
    if result.takeover_vulnerable:
        print(f"      TAKEOVER: {result.takeover_details}")
    if verbose:
        if result.policy:
            print(f"      Policy: {json.dumps(result.policy, indent=2)[:400]}")
        if result.sample_keys:
            print(f"      Samples: {result.sample_keys[:5]}")


async def run_scan(args: argparse.Namespace) -> List:
    domains = [args.domain]
    wordlist = []
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)

    config = ScanConfig(
        domains=domains,
        wordlist=wordlist,
        permutations=not args.no_permutations,
        max_workers=args.workers,
        timeout=args.timeout,
        providers=args.providers,
        aws_keys=tuple(args.aws_keys) if args.aws_keys else None,
        gcp_token=args.gcp_token,
        azure_sas=args.azure_sas,
        proxy=args.proxy,
        stealth=args.stealth,
        content_analysis=not args.no_content_analysis,
        dns_lookup=not args.no_dns,
        all_regions=args.all_regions,
        adaptive_rate_limit=not args.no_rate_limit,
        enumerate_policies=not args.no_policy,
        test_presigned_urls=not args.no_presigned,
        takeover_check=not args.no_takeover,
        entropy_analysis=not args.no_entropy,
    )

    async with CloudBucketScanner(config) as scanner:
        results = await scanner.scan_all()
        return results


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        results = asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130

    if not results:
        print("[!] No results found")
        return 0

    print(f"\n[+] Scan complete: {len(results)} buckets probed\n")

    for r in results:
        if r.exposure not in ("not_found", "error", "INFO") or args.verbose:
            print_result(r, args.verbose)

    if args.output:
        out = []
        for r in results:
            d = {}
            for k, v in r.__dict__.items():
                if isinstance(v, set):
                    v = list(v)
                d[k] = v
            out.append(d)
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
