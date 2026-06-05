#!/usr/bin/env python3
"""Tests for BlackCloud scanner module."""

import pytest
import asyncio
from blackcloud.scanner import CloudBucketScanner, AdaptiveRateLimiter, AWS_REGIONS
from blackcloud.models import ScanConfig, BucketResult


def test_adaptive_rate_limiter():
    rl = AdaptiveRateLimiter(max_rate=10.0, min_rate=2.0)
    assert rl.current_rate == 10.0
    for _ in range(4):
        rl.report_error()
    rl.requests_since_adapt = 10
    rl._adapt()
    assert rl.current_rate < 10.0


@pytest.mark.asyncio
async def test_rate_limiter_acquire():
    rl = AdaptiveRateLimiter(max_rate=100.0)
    await rl.acquire()
    assert rl.tokens <= 100.0


def test_generate_permutations():
    config = ScanConfig(domains=["example"])
    scanner = CloudBucketScanner(config)
    perms = scanner.generate_permutations(["example"])
    assert len(perms) > 100
    assert "example" in perms
    assert "example-backup" in perms
    assert "backup-example" in perms


def test_classify_exposure():
    config = ScanConfig(domains=["test"])
    scanner = CloudBucketScanner(config)
    assert scanner._classify_exposure(200, "<ListBucketResult>", "aws") == "listable_full"
    assert scanner._classify_exposure(403, "AccessDenied", "aws") == "exists_denied"
    assert scanner._classify_exposure(404, "NoSuchBucket", "aws") == "not_found"
    assert scanner._classify_exposure(301, "", "aws") == "redirect"


def test_extract_keys_aws():
    config = ScanConfig(domains=["test"])
    scanner = CloudBucketScanner(config)
    body = '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Contents><Key>file1.txt</Key></Contents><Contents><Key>file2.txt</Key></Contents></ListBucketResult>'
    keys = scanner._extract_keys(body, "aws")
    assert keys == ["file1.txt", "file2.txt"]


def test_aws_regions_count():
    assert len(AWS_REGIONS) == 31


@pytest.mark.asyncio
async def test_scanner_context_manager():
    config = ScanConfig(domains=["test"])
    async with CloudBucketScanner(config) as scanner:
        assert scanner._session is not None
