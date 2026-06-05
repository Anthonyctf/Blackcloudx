#!/usr/bin/env python3
"""Tests for BlackCloud models."""

import pytest
from blackcloud.models import BucketResult, ScanConfig


def test_bucket_result_defaults():
    r = BucketResult(provider="aws", service="s3", bucket="test", url="http://test", status=200, exposure="listable_full")
    assert r.provider == "aws"
    assert r.sample_keys == []
    assert r.pii_findings == {}
    assert r.error is None
    assert r.timestamp is not None


def test_scan_config_defaults():
    c = ScanConfig(domains=["example.com"])
    assert c.domains == ["example.com"]
    assert c.providers == ["aws", "gcp", "azure"]
    assert c.max_workers == 50
    assert c.timeout == 15
    assert c.permutations is True


def test_bucket_result_serialization():
    r = BucketResult(provider="gcp", service="gcs", bucket="b", url="http://b", status=404, exposure="not_found")
    d = r.__dict__
    assert d["provider"] == "gcp"
    assert d["status"] == 404
