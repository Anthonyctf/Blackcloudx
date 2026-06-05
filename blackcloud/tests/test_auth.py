#!/usr/bin/env python3
"""Tests for BlackCloud auth modules."""

import pytest
from blackcloud.auth import AWSAuth, GCPAuth, AzureAuth


def test_gcp_auth_headers():
    auth = GCPAuth("token123")
    headers = auth.headers()
    assert headers["Authorization"] == "Bearer token123"


def test_azure_auth_append():
    auth = AzureAuth("sv=2020-08-04&ss=b")
    assert auth.append_to_url("https://x.blob.core.windows.net") == "https://x.blob.core.windows.net?sv=2020-08-04&ss=b"
    assert "&" in auth.append_to_url("https://x.blob.core.windows.net?foo=1")


def test_aws_sign_headers_present():
    auth = AWSAuth("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    headers = auth.sign("GET", "https://test.s3.us-east-1.amazonaws.com/", {})
    assert "Authorization" in headers
    assert "x-amz-date" in headers
    assert "host" in headers


def test_aws_presign_contains_signature():
    auth = AWSAuth("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    url = auth.presign("GET", "https://test.s3.us-east-1.amazonaws.com/", expires=3600)
    assert "X-Amz-Signature=" in url
    assert "X-Amz-Credential=" in url


def test_aws_region_from_host():
    auth = AWSAuth("A", "S")
    assert auth._region_from_host("test.s3.eu-west-1.amazonaws.com") == "eu-west-1"
    assert auth._region_from_host("test.s3.amazonaws.com") == "us-east-1"
