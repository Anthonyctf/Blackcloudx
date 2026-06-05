#!/usr/bin/env python3
"""BlackCloud - Data Models"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


@dataclass
class BucketResult:
    provider: str
    service: str
    bucket: str
    url: str
    status: int
    exposure: str
    region: Optional[str] = None
    auth_tested: bool = False
    auth_bypass: bool = False
    keys_count: int = 0
    sample_keys: List[str] = field(default_factory=list)
    sensitive_keys: List[str] = field(default_factory=list)
    pii_findings: Dict[str, List[str]] = field(default_factory=dict)
    entropy_findings: List[Dict[str, Any]] = field(default_factory=list)
    cname: Optional[str] = None
    redirect_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: Optional[str] = None
    policy: Optional[Dict[str, Any]] = None
    acl: Optional[Dict[str, Any]] = None
    cors: Optional[Dict[str, Any]] = None
    versioning: Optional[str] = None
    encryption: Optional[str] = None
    mfa_delete: Optional[str] = None
    website_hosting: Optional[str] = None
    logging_enabled: Optional[bool] = None
    object_lock: Optional[str] = None
    lifecycle_rules: Optional[List[Dict[str, Any]]] = None
    presigned_url_works: Optional[bool] = None
    takeover_vulnerable: Optional[bool] = None
    takeover_details: Optional[str] = None
    rate_limit_hit: bool = False
    response_time_ms: Optional[float] = None


@dataclass
class ScanConfig:
    domains: List[str]
    wordlist: List[str] = field(default_factory=list)
    permutations: bool = True
    max_workers: int = 50
    timeout: int = 15
    providers: List[str] = field(default_factory=lambda: ["aws", "gcp", "azure"])
    aws_keys: Optional[tuple] = None
    gcp_token: Optional[str] = None
    azure_sas: Optional[str] = None
    proxy: Optional[str] = None
    stealth: bool = False
    content_analysis: bool = True
    dns_lookup: bool = True
    all_regions: bool = False
    adaptive_rate_limit: bool = True
    enumerate_policies: bool = True
    test_presigned_urls: bool = True
    takeover_check: bool = True
    entropy_analysis: bool = True
