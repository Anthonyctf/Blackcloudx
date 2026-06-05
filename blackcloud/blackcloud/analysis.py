#!/usr/bin/env python3
"""BlackCloud - Content Analysis & Entropy Detection"""

import re
import math
import string
from typing import Dict, List, Tuple, Any, Optional


ENTROPY_THRESHOLDS = {
    "base64": 4.5,
    "hex": 3.0,
    "generic": 4.0,
}

PII_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"['\"`]([0-9a-zA-Z/+]{40})['\"`]"),
    "gcp_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "gcp_oauth_id": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "github_classic": re.compile(r"[0-9a-f]{40}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}"),
    "private_key": re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "password_line": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"`]?[^\s'\"`]+"),
    "db_connection": re.compile(r"(?i)(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://|mssql://)"),
    "token_bearer": re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+"),
    "api_key_header": re.compile(r"(?i)x-api-key\s*[:=]\s*['\"`]?[^\s'\"`]+"),
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
    "stripe_key": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
    "twilio_sid": re.compile(r"AC[a-zA-Z0-9]{32}"),
    "twilio_token": re.compile(r"[0-9a-f]{32}"),
    "azure_storage_key": re.compile(r"AccountKey=[a-zA-Z0-9+/=]{88}"),
    "s3_url_with_key": re.compile(r"s3://[^:]+:[^@]+@s3\.amazonaws\.com"),
}

SENSITIVE_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".der",
    ".env", ".config", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml",
    ".sql", ".dump", ".bak", ".backup", ".zip", ".tar", ".gz", ".tgz",
    ".csv", ".xls", ".xlsx", ".db", ".sqlite", ".sqlite3", ".mdb",
    ".tfstate", ".tfvars", ".ansible", ".puppet", ".chef",
    ".kube", ".kubectl", ".docker", ".dockercfg",
    ".htpasswd", ".netrc", ".npmrc", ".pypirc",
    ".jks", ".keystore", ".truststore",
    ".ovpn", ".conf", ".credentials", ".secret",
    ".htaccess", ".passwd", ".shadow", ".gpg", ".asc",
}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for count in {c: data.count(c) for c in set(data)}.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def is_base64(s: str) -> bool:
    if len(s) < 20:
        return False
    base64_chars = set(string.ascii_letters + string.digits + "+/=")
    return all(c in base64_chars for c in s) and len(s) % 4 == 0


def is_hex(s: str) -> bool:
    if len(s) < 20:
        return False
    hex_chars = set(string.hexdigits)
    return all(c in hex_chars for c in s)


def find_high_entropy_strings(text: str, min_length: int = 20) -> List[Dict[str, Any]]:
    findings = []
    tokens = re.split(r'[\s"\'`\n\r\t,;|<>{}\[\]]+', text)
    seen = set()

    for token in tokens:
        token = token.strip()
        if len(token) < min_length or token in seen:
            continue
        seen.add(token)

        entropy = shannon_entropy(token)
        token_type = "generic"
        threshold = ENTROPY_THRESHOLDS["generic"]

        if is_base64(token):
            token_type = "base64"
            threshold = ENTROPY_THRESHOLDS["base64"]
        elif is_hex(token):
            token_type = "hex"
            threshold = ENTROPY_THRESHOLDS["hex"]

        if entropy >= threshold:
            if re.match(r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$", token):
                continue
            if re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}", token):
                continue
            if re.match(r"^[0-9a-f]{64}$", token.lower()) and entropy < 4.5:
                continue

            findings.append({
                "token": token[:80] + "..." if len(token) > 80 else token,
                "type": token_type,
                "entropy": round(entropy, 3),
                "length": len(token),
            })

    findings.sort(key=lambda x: x["entropy"], reverse=True)
    return findings[:50]


def analyze_content(keys: List[str], body: str) -> Tuple[List[str], Dict[str, List[str]], List[Dict[str, Any]]]:
    sensitive = []
    for key in keys:
        low = key.lower()
        if any(low.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
            sensitive.append(key)

    pii_findings: Dict[str, List[str]] = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(body)
        if matches:
            flat = []
            for m in matches:
                if isinstance(m, tuple):
                    flat.extend([x for x in m if x])
                else:
                    flat.append(m)
            if flat:
                pii_findings[pii_type] = list(set(flat))[:20]

    entropy_findings = find_high_entropy_strings(body)
    return sensitive, pii_findings, entropy_findings


def classify_bucket_risk(
    exposure: str,
    sensitive_keys: List[str],
    pii_findings: Dict[str, List[str]],
    entropy_findings: List[Dict[str, Any]],
    policy: Optional[Dict[str, Any]] = None,
) -> str:
    if exposure.startswith("listable"):
        if pii_findings or entropy_findings:
            return "CRITICAL"
        if sensitive_keys:
            return "HIGH"
        return "MEDIUM"
    elif exposure == "accessible":
        return "LOW"
    elif exposure == "exists_denied":
        return "INFO"
    return "INFO"
