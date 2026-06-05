#!/usr/bin/env python3
"""BlackCloud - Bucket Takeover Detection"""

import aiohttp
from typing import Optional, Dict, Any


async def check_s3_takeover(
    session: aiohttp.ClientSession,
    bucket: str,
    region: str,
    semaphore,
    timeout,
) -> Optional[Dict[str, Any]]:
    url = f"https://{bucket}.s3.{region}.amazonaws.com"
    try:
        async with semaphore:
            async with session.get(url, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 404 and "NoSuchBucket" in body:
                    return {
                        "vulnerable": True,
                        "provider": "aws",
                        "bucket": bucket,
                        "region": region,
                        "reason": "Bucket does not exist - CNAME may be dangling",
                        "severity": "HIGH",
                    }
                elif resp.status == 404:
                    return {
                        "vulnerable": True,
                        "provider": "aws",
                        "bucket": bucket,
                        "region": region,
                        "reason": "Bucket deleted or never existed",
                        "severity": "MEDIUM",
                    }
    except Exception:
        pass
    return None


async def check_gcp_takeover(
    session: aiohttp.ClientSession,
    bucket: str,
    semaphore,
    timeout,
) -> Optional[Dict[str, Any]]:
    url = f"https://storage.googleapis.com/{bucket}"
    try:
        async with semaphore:
            async with session.get(url, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 404 and "NoSuchBucket" in body:
                    return {
                        "vulnerable": True,
                        "provider": "gcp",
                        "bucket": bucket,
                        "reason": "Bucket does not exist - may be hijackable",
                        "severity": "HIGH",
                    }
    except Exception:
        pass
    return None


async def check_azure_takeover(
    session: aiohttp.ClientSession,
    bucket: str,
    semaphore,
    timeout,
) -> Optional[Dict[str, Any]]:
    url = f"https://{bucket}.blob.core.windows.net"
    try:
        async with semaphore:
            async with session.get(url, timeout=timeout, allow_redirects=False) as resp:
                body = await resp.text()
                if resp.status == 404:
                    return {
                        "vulnerable": True,
                        "provider": "azure",
                        "bucket": bucket,
                        "reason": "Container does not exist - may be hijackable",
                        "severity": "HIGH",
                    }
    except Exception:
        pass
    return None


async def check_takeover(
    session: aiohttp.ClientSession,
    bucket: str,
    provider: str,
    region: Optional[str],
    semaphore,
    timeout,
) -> Optional[Dict[str, Any]]:
    if provider in ("aws", "s3"):
        region = region or "us-east-1"
        return await check_s3_takeover(session, bucket, region, semaphore, timeout)
    elif provider in ("gcp", "gcs"):
        return await check_gcp_takeover(session, bucket, semaphore, timeout)
    elif provider in ("azure", "blob"):
        return await check_azure_takeover(session, bucket, semaphore, timeout)
    return None
