#!/usr/bin/env python3
"""BlackCloud - Bucket Policy Enumeration"""

import json
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Any, List
import aiohttp


async def fetch_s3_bucket_policy(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[Dict[str, Any]]:
    url = f"{bucket_url}?policy"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    try:
                        return json.loads(body)
                    except json.JSONDecodeError:
                        return {"raw": body}
                elif resp.status == 403:
                    return {"access_denied": True, "raw": body}
                elif resp.status == 404:
                    return {"no_policy": True}
    except Exception:
        pass
    return None


async def fetch_s3_acl(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[Dict[str, Any]]:
    url = f"{bucket_url}?acl"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    return _parse_acl_xml(body)
                elif resp.status == 403:
                    return {"access_denied": True}
    except Exception:
        pass
    return None


def _parse_acl_xml(xml_body: str) -> Dict[str, Any]:
    result = {"grants": []}
    try:
        root = ET.fromstring(xml_body)
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        for grant in root.iter(f"{ns}Grant"):
            grantee = grant.find(f"{ns}Grantee")
            permission = grant.find(f"{ns}Permission")
            if grantee is not None and permission is not None:
                result["grants"].append({
                    "type": grantee.get(f"{{{ns}}}type", ""),
                    "uri": grantee.get("URI", ""),
                    "display_name": grantee.findtext(f"{ns}DisplayName", ""),
                    "permission": permission.text or "",
                })
    except ET.ParseError:
        result["raw"] = xml_body
    return result


async def fetch_s3_versioning(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[str]:
    url = f"{bucket_url}?versioning"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    if "Enabled" in body:
                        return "Enabled"
                    elif "Suspended" in body:
                        return "Suspended"
                    return "Disabled"
    except Exception:
        pass
    return None


async def fetch_s3_encryption(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[str]:
    url = f"{bucket_url}?encryption"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    if "AES256" in body:
                        return "AES256 (SSE-S3)"
                    elif "aws:kms" in body:
                        return "AWS-KMS (SSE-KMS)"
                    elif "DSSE-KMS" in body:
                        return "DSSE-KMS"
                    return "Custom"
                elif resp.status == 404:
                    return "None"
    except Exception:
        pass
    return None


async def fetch_s3_website(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[str]:
    url = f"{bucket_url}?website"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    return "Enabled"
                elif resp.status == 404:
                    return "Disabled"
    except Exception:
        pass
    return None


async def fetch_s3_logging(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[bool]:
    url = f"{bucket_url}?logging"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    return "<LoggingEnabled>" in body
    except Exception:
        pass
    return None


async def fetch_s3_object_lock(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[str]:
    url = f"{bucket_url}?object-lock"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    return "Enabled"
                elif resp.status == 404:
                    return "Disabled"
    except Exception:
        pass
    return None


async def fetch_s3_lifecycle(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Optional[List]:
    url = f"{bucket_url}?lifecycle"
    try:
        async with semaphore:
            async with session.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 200:
                    return _parse_lifecycle_xml(body)
                elif resp.status == 404:
                    return []
    except Exception:
        pass
    return None


def _parse_lifecycle_xml(xml_body: str) -> List:
    rules = []
    try:
        root = ET.fromstring(xml_body)
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        for rule in root.iter(f"{ns}Rule"):
            rule_data = {}
            id_elem = rule.find(f"{ns}ID")
            if id_elem is not None:
                rule_data["id"] = id_elem.text
            status_elem = rule.find(f"{ns}Status")
            if status_elem is not None:
                rule_data["status"] = status_elem.text
            prefix_elem = rule.find(f"{ns}Prefix")
            if prefix_elem is not None:
                rule_data["prefix"] = prefix_elem.text
            rules.append(rule_data)
    except ET.ParseError:
        pass
    return rules


async def enumerate_s3_bucket(
    session: aiohttp.ClientSession,
    bucket_url: str,
    auth_headers: Dict[str, str],
    semaphore,
    timeout,
) -> Dict[str, Any]:
    results = {}
    tasks = [
        ("policy", fetch_s3_bucket_policy(session, bucket_url, auth_headers, semaphore, timeout)),
        ("acl", fetch_s3_acl(session, bucket_url, auth_headers, semaphore, timeout)),
        ("versioning", fetch_s3_versioning(session, bucket_url, auth_headers, semaphore, timeout)),
        ("encryption", fetch_s3_encryption(session, bucket_url, auth_headers, semaphore, timeout)),
        ("website_hosting", fetch_s3_website(session, bucket_url, auth_headers, semaphore, timeout)),
        ("logging_enabled", fetch_s3_logging(session, bucket_url, auth_headers, semaphore, timeout)),
        ("object_lock", fetch_s3_object_lock(session, bucket_url, auth_headers, semaphore, timeout)),
        ("lifecycle_rules", fetch_s3_lifecycle(session, bucket_url, auth_headers, semaphore, timeout)),
    ]

    for name, coro in tasks:
        try:
            result = await coro
            if result is not None:
                results[name] = result
        except Exception:
            continue

    return results
