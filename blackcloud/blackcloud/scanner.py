#!/usr/bin/env python3
"""BlackCloud - Async Multi-Cloud Bucket Scanner Engine"""

import asyncio
import aiohttp
import aiodns
import random
import time
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any, AsyncGenerator
from urllib.parse import urlparse

from .models import BucketResult, ScanConfig
from .auth import AWSAuth, GCPAuth, AzureAuth
from .analysis import analyze_content, classify_bucket_risk
from .policy import enumerate_s3_bucket
from .takeover import check_takeover


AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "af-south-1", "ap-east-1", "ap-south-1", "ap-south-2",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ca-central-1", "ca-west-1", "eu-central-1", "eu-central-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-south-1", "eu-south-2",
    "eu-north-1", "il-central-1", "me-central-1", "me-south-1",
    "sa-east-1", "us-gov-east-1", "us-gov-west-1",
]

BREACH_WORDLIST = [
    "backup", "backups", "bak", "archive", "archives", "dump", "dumps",
    "dev", "devel", "development", "staging", "stage", "test", "testing",
    "prod", "production", "uat", "qa", "demo", "sandbox", "tmp", "temp",
    "logs", "log", "data", "assets", "uploads", "files", "media",
    "config", "configs", "conf", "secrets", "secret", "credentials",
    "creds", "keys", "key", "private", "ssl", "tls", "certs", "certificates",
    "db", "database", "sql", "mongo", "redis", "postgres", "mysql",
    "images", "img", "docs", "documents", "reports", "export", "exports",
    "import", "imports", "download", "downloads", "public", "static",
    "old", "new", "v1", "v2", "v3", "api", "rest", "graphql", "web",
    "mobile", "ios", "android", "frontend", "backend", "infra",
    "infrastructure", "terraform", "ansible", "chef", "puppet",
    "ci", "cd", "jenkins", "gitlab", "github", "bitbucket",
    "s3", "gcs", "azure", "cloud", "bucket", "storage", "store",
    "shared", "common", "default", "main", "master", "release",
    "build", "artifacts", "packages", "npm", "pypi", "docker",
    "kubernetes", "k8s", "helm", "charts", "monitoring", "metrics",
    "tracing", "events", "alarms", "notifications", "email",
    "mail", "smtp", "ftp", "sftp", "scp", "transfer", "sync",
    "batch", "etl", "pipeline", "jobs", "cron", "scheduled",
    "serverless", "lambda", "functions", "workers", "queue",
    "cache", "cdn", "edge", "firewall", "waf", "security",
    "compliance", "audit", "legal", "hr", "finance", "accounting",
    "billing", "invoices", "payments", "transactions", "orders",
    "customers", "users", "clients", "partners", "vendors",
    "employees", "internal", "restricted", "classified", "confidential",
]


class AdaptiveRateLimiter:
    """Token-bucket style adaptive rate limiter with congestion backoff."""

    def __init__(self, max_rate: float = 50.0, min_rate: float = 5.0, adapt_interval: int = 10):
        self.max_rate = max_rate
        self.min_rate = min_rate
        self.current_rate = max_rate
        self.tokens = max_rate
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()
        self.requests_since_adapt = 0
        self.errors_since_adapt = 0
        self.adapt_interval = adapt_interval

    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.current_rate, self.tokens + elapsed * self.current_rate)
            self.last_update = now

            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.current_rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0

            self.requests_since_adapt += 1
            if self.requests_since_adapt >= self.adapt_interval:
                self._adapt()

    def _adapt(self):
        ratio = self.errors_since_adapt / max(1, self.requests_since_adapt)
        if ratio > 0.3:
            self.current_rate = max(self.min_rate, self.current_rate * 0.7)
        elif ratio < 0.05 and self.current_rate < self.max_rate:
            self.current_rate = min(self.max_rate, self.current_rate * 1.1)
        self.requests_since_adapt = 0
        self.errors_since_adapt = 0

    def report_error(self):
        self.errors_since_adapt += 1


class CloudBucketScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.rate_limiter = AdaptiveRateLimiter(
            max_rate=config.max_workers,
            min_rate=5.0,
        ) if config.adaptive_rate_limit else None
        self.semaphore = asyncio.Semaphore(config.max_workers)
        self.timeout = aiohttp.ClientTimeout(total=config.timeout)
        self.results: List[BucketResult] = []
        self.dns_resolver: Optional[aiodns.DNSResolver] = None
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=200, limit_per_host=50, ssl=False)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={"User-Agent": self._get_ua()},
        )
        if self.config.dns_lookup:
            self.dns_resolver = aiodns.DNSResolver()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
        return False

    def _get_ua(self) -> str:
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "curl/7.88.1",
            "aws-cli/2.13.0 Python/3.11.0",
        ]
        return random.choice(uas)

    def generate_permutations(self, base_names: List[str]) -> List[str]:
        names = set(base_names)
        for base in list(base_names):
            base = base.lower().strip()
            if not base:
                continue
            names.add(base)
            names.add(base.replace(".", "-"))
            names.add(base.replace("-", ""))
            names.add(base.replace("_", "-"))
            names.add(base.replace("-", "_"))
            for word in BREACH_WORDLIST:
                names.add(f"{base}-{word}")
                names.add(f"{word}-{base}")
                names.add(f"{base}{word}")
                names.add(f"{word}{base}")
                names.add(f"{base}_{word}")
                names.add(f"{word}_{base}")
        return sorted(names)

    async def resolve_cname(self, hostname: str) -> Optional[str]:
        if not self.dns_resolver:
            return None
        try:
            result = await self.dns_resolver.query(hostname, "CNAME")
            if result and hasattr(result, "cname"):
                return result.cname
            elif result and isinstance(result, list) and len(result) > 0:
                return result[0].cname
        except Exception:
            pass
        return None

    async def _rl_acquire(self):
        if self.rate_limiter:
            await self.rate_limiter.acquire()

    async def _rl_error(self):
        if self.rate_limiter:
            self.rate_limiter.report_error()

    async def scan_all(self) -> List[BucketResult]:
        targets: List[Dict[str, Any]] = []
        for domain in self.config.domains:
            targets.append({"name": domain, "source": "direct"})

        if self.config.permutations:
            perms = self.generate_permutations(self.config.domains)
            for p in perms:
                if p not in {t["name"] for t in targets}:
                    targets.append({"name": p, "source": "permutation"})

        tasks = []
        for provider in self.config.providers:
            for target in targets:
                tasks.append(self._probe_provider(provider, target["name"]))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.results = [r for r in results if isinstance(r, BucketResult)]
        return self.results

    async def _probe_provider(self, provider: str, bucket: str) -> Optional[BucketResult]:
        if provider in ("aws", "s3"):
            return await self._probe_aws(bucket)
        elif provider in ("gcp", "gcs"):
            return await self._probe_gcp(bucket)
        elif provider in ("azure", "blob"):
            return await self._probe_azure(bucket)
        return None

    async def _probe_aws(self, bucket: str) -> Optional[BucketResult]:
        regions = AWS_REGIONS if self.config.all_regions else ["us-east-1"]
        for region in regions:
            url = f"https://{bucket}.s3.{region}.amazonaws.com"
            result = await self._check_bucket(url, bucket, "aws", "s3", region)
            if result and result.status != 404:
                return result
        return await self._check_bucket(
            f"https://{bucket}.s3.amazonaws.com", bucket, "aws", "s3", "us-east-1"
        )

    async def _probe_gcp(self, bucket: str) -> Optional[BucketResult]:
        url = f"https://storage.googleapis.com/{bucket}"
        return await self._check_bucket(url, bucket, "gcp", "gcs", None)

    async def _probe_azure(self, bucket: str) -> Optional[BucketResult]:
        url = f"https://{bucket}.blob.core.windows.net"
        return await self._check_bucket(url, bucket, "azure", "blob", None)

    async def _check_bucket(
        self,
        url: str,
        bucket: str,
        provider: str,
        service: str,
        region: Optional[str],
    ) -> Optional[BucketResult]:
        if not self._session:
            return None

        start = time.monotonic()
        try:
            await self._rl_acquire()
            async with self.semaphore:
                async with self._session.get(url, timeout=self.timeout, allow_redirects=False) as resp:
                    body = await resp.text()
                    status = resp.status
                    headers = dict(resp.headers)
        except Exception as e:
            self._rl_error()
            return BucketResult(
                provider=provider,
                service=service,
                bucket=bucket,
                url=url,
                status=0,
                exposure="error",
                region=region,
                error=str(e),
            )

        response_time = round((time.monotonic() - start) * 1000, 2)

        exposure = self._classify_exposure(status, body, provider)
        result = BucketResult(
            provider=provider,
            service=service,
            bucket=bucket,
            url=url,
            status=status,
            exposure=exposure,
            region=region,
            headers=headers,
            response_time_ms=response_time,
        )

        if status == 429 or status == 503:
            result.rate_limit_hit = True
            self._rl_error()

        if self.config.dns_lookup and exposure != "not_found":
            parsed = urlparse(url)
            cname = await self.resolve_cname(parsed.netloc)
            if cname:
                result.cname = cname

        if exposure.startswith("listable") or exposure == "accessible":
            keys = self._extract_keys(body, provider)
            result.keys_count = len(keys)
            result.sample_keys = keys[:50]

            if self.config.content_analysis and keys:
                sample_body = body[:50000]
                sensitive, pii, entropy = analyze_content(keys, sample_body)
                result.sensitive_keys = sensitive
                result.pii_findings = pii
                result.entropy_findings = entropy

            if self.config.enumerate_policies and provider == "aws":
                auth_headers = {}
                if self.config.aws_keys:
                    aws_auth = AWSAuth(*self.config.aws_keys)
                    auth_headers = aws_auth.sign("GET", url, {})
                policy_data = await enumerate_s3_bucket(self._session, url, auth_headers, self.semaphore, self.timeout)
                for k, v in policy_data.items():
                    if hasattr(result, k):
                        setattr(result, k, v)

            if self.config.test_presigned_urls and self.config.aws_keys and provider == "aws":
                aws_auth = AWSAuth(*self.config.aws_keys)
                presigned = aws_auth.presign("GET", url, expires=300)
                try:
                    async with self.semaphore:
                        async with self._session.get(presigned, timeout=self.timeout, allow_redirects=False) as pr:
                            result.presigned_url_works = pr.status < 400
                except Exception:
                    result.presigned_url_works = False

        if self.config.takeover_check and exposure == "not_found":
            takeover = await check_takeover(self._session, bucket, provider, region, self.semaphore, self.timeout)
            if takeover:
                result.takeover_vulnerable = takeover.get("vulnerable")
                result.takeover_details = takeover.get("reason")

        result.auth_tested = bool(self.config.aws_keys or self.config.gcp_token or self.config.azure_sas)
        result.auth_bypass = False

        result.exposure = classify_bucket_risk(
            result.exposure,
            result.sensitive_keys,
            result.pii_findings,
            result.entropy_findings,
            result.policy,
        )
        return result

    def _classify_exposure(self, status: int, body: str, provider: str) -> str:
        if status == 200:
            if "<ListBucketResult" in body or "<Name>" in body:
                return "listable_full"
            elif "<Contents>" in body:
                return "listable_full"
            else:
                return "accessible"
        elif status == 403:
            if provider == "aws" and "AccessDenied" in body:
                return "exists_denied"
            return "exists_denied"
        elif status == 404:
            if provider == "aws" and "NoSuchBucket" in body:
                return "not_found"
            elif provider == "gcp" and "NoSuchBucket" in body:
                return "not_found"
            return "not_found"
        elif status == 301:
            return "redirect"
        elif status in (400, 401):
            return "exists_denied"
        return "unknown"

    def _extract_keys(self, body: str, provider: str) -> List[str]:
        keys = []
        if provider in ("aws", "s3") and "<ListBucketResult" in body:
            try:
                root = ET.fromstring(body.encode())
                ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
                for key in root.iter(f"{ns}Key"):
                    if key.text:
                        keys.append(key.text)
            except ET.ParseError:
                keys = re.findall(r"<Key>([^<]+)</Key>", body)
        elif provider in ("gcp", "gcs") and "<Name>" in body:
            keys = re.findall(r"<Name>([^<]+)</Name>", body)
        elif provider in ("azure", "blob") and "<Name>" in body:
            keys = re.findall(r"<Name>([^<]+)</Name>", body)
        return keys

    async def scan_targets(self, targets: List[Dict[str, str]]) -> AsyncGenerator[BucketResult, None]:
        tasks = []
        for t in targets:
            provider = t.get("provider", "aws")
            bucket = t["bucket"]
            tasks.append(self._probe_provider(provider, bucket))

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                yield result

    def get_results_by_risk(self) -> Dict[str, List[BucketResult]]:
        grouped: Dict[str, List[BucketResult]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for r in self.results:
            risk = getattr(r, "exposure", "INFO")
            if risk in grouped:
                grouped[risk].append(r)
            else:
                grouped["INFO"].append(r)
        return grouped
