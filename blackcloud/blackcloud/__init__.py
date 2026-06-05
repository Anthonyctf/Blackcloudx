"""
BlackCloud - Expert-Tier Multi-Cloud Storage Bucket Scanner

A bleeding-edge reconnaissance tool for hunting exposed S3, GCS, and Azure Blob Storage
with adaptive rate limiting, policy enumeration, takeover detection, entropy analysis,
and authenticated ACL bypass testing.

Author: Valley
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Valley"
__license__ = "MIT"

from .models import BucketResult, ScanConfig
from .auth import AWSAuth, GCPAuth, AzureAuth
from .analysis import analyze_content, classify_bucket_risk, shannon_entropy, find_high_entropy_strings
from .scanner import CloudBucketScanner

__all__ = [
    "CloudBucketScanner",
    "BucketResult",
    "ScanConfig",
    "AWSAuth",
    "GCPAuth",
    "AzureAuth",
    "analyze_content",
    "classify_bucket_risk",
    "shannon_entropy",
    "find_high_entropy_strings",
]
