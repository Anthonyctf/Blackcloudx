#!/usr/bin/env python3
"""BlackCloud - Authentication Modules"""

import hashlib
import hmac
import base64
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, quote
from typing import Dict, Optional


class AWSAuth:
    """AWS Signature Version 4 signer."""

    def __init__(self, access_key: str, secret_key: str, session_token: Optional[str] = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token

    def sign(self, method: str, url: str, headers: Dict[str, str], payload: bytes = b"") -> Dict[str, str]:
        parsed = urlparse(url)
        host = parsed.netloc
        uri = parsed.path or "/"
        query = parsed.query

        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        hdrs = dict(headers)
        hdrs["host"] = host
        hdrs["x-amz-date"] = amz_date
        hdrs["x-amz-content-sha256"] = hashlib.sha256(payload).hexdigest()
        if self.session_token:
            hdrs["x-amz-security-token"] = self.session_token

        signed_headers = ";".join(sorted(k.lower() for k in hdrs.keys()))
        canonical_headers = "\n".join(f"{k.lower()}:{hdrs[k].strip()}" for k in sorted(hdrs.keys())) + "\n"

        payload_hash = hashlib.sha256(payload).hexdigest()
        canonical_request = "\n".join([
            method, uri, query,
            canonical_headers, signed_headers, payload_hash,
        ])

        algorithm = "AWS4-HMAC-SHA256"
        region = self._region_from_host(host)
        credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
        string_to_sign = "\n".join([
            algorithm, amz_date, credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])

        signing_key = self._get_signing_key(date_stamp, region)
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

        auth_header = (
            f"{algorithm} Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        hdrs["Authorization"] = auth_header
        return hdrs

    def presign(self, method: str, url: str, expires: int = 3600) -> str:
        parsed = urlparse(url)
        host = parsed.netloc
        uri = parsed.path or "/"
        region = self._region_from_host(host)
        date_stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        params = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": f"{self.access_key}/{date_stamp}/{region}/s3/aws4_request",
            "X-Amz-Date": amz_date,
            "X-Amz-Expires": str(expires),
            "X-Amz-SignedHeaders": "host",
        }
        if self.session_token:
            params["X-Amz-Security-Token"] = self.session_token

        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in sorted(params.items()))
        canonical_request = "\n".join([
            method, uri, query,
            "host:" + host + "\n", "host", "UNSIGNED-PAYLOAD",
        ])

        credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])

        signing_key = self._get_signing_key(date_stamp, region)
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        return f"{url}?{query}&X-Amz-Signature={signature}"

    def _region_from_host(self, host: str) -> str:
        match = re.search(r"s3[-.]([a-z0-9-]+)\.amazonaws\.com", host)
        if match:
            return match.group(1)
        return "us-east-1"

    def _get_signing_key(self, date_stamp: str, region: str) -> bytes:
        k_date = hmac.new(f"AWS4{self.secret_key}".encode(), date_stamp.encode(), hashlib.sha256).digest()
        k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
        k_service = hmac.new(k_region, b"s3", hashlib.sha256).digest()
        return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()


class GCPAuth:
    def __init__(self, token: str):
        self.token = token

    def headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


class AzureAuth:
    def __init__(self, sas_token: str):
        self.sas_token = sas_token

    def append_to_url(self, url: str) -> str:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{self.sas_token}"
