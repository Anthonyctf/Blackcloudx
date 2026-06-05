#!/usr/bin/env python3
"""Tests for BlackCloud analysis module."""

from blackcloud.analysis import (
    shannon_entropy,
    is_base64,
    is_hex,
    find_high_entropy_strings,
    analyze_content,
    classify_bucket_risk,
)


def test_shannon_entropy_known():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    ent = shannon_entropy("abcd")
    assert 1.9 < ent < 2.1


def test_is_base64():
    assert is_base64("aGVsbG8gd29ybGQgYWJjZGVmZ2hpamtsbW5vcHFyc3Q=") is True
    assert is_base64("short") is False
    assert is_base64("!!!") is False


def test_is_hex():
    assert is_hex("deadbeef1234567890abcdef12345678") is True
    assert is_hex("nothex") is False


def test_find_high_entropy_strings():
    text = "low low low " + "aGVsbG8gd29ybGQgYWJjZGVmZ2hpamtsbW5vcHFyc3Q=" * 5
    findings = find_high_entropy_strings(text)
    assert len(findings) > 0
    assert findings[0]["type"] == "base64"


def test_analyze_content_finds_sensitive():
    keys = ["config.env", "backup.sql", "image.png"]
    body = "AKIAIOSFODNN7EXAMPLE some text password='secret123'"
    sensitive, pii, entropy = analyze_content(keys, body)
    assert "config.env" in sensitive
    assert "backup.sql" in sensitive
    assert "image.png" not in sensitive
    assert "aws_access_key" in pii
    assert "password_line" in pii


def test_classify_bucket_risk():
    assert classify_bucket_risk("listable_full", [], {}, []) == "MEDIUM"
    assert classify_bucket_risk("listable_full", ["a.env"], {}, []) == "HIGH"
    assert classify_bucket_risk("accessible", [], {}, []) == "LOW"
    assert classify_bucket_risk("exists_denied", [], {}, []) == "INFO"
