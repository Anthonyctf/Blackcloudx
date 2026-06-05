# Changelog

All notable changes to BlackCloud will be documented in this file.

## [1.0.0] - 2026-06-05

### Added
- Initial release of BlackCloud
- Multi-cloud support: AWS S3 (31 regions), Google Cloud Storage, Azure Blob Storage
- Adaptive rate limiting with congestion backoff
- 100+ naming permutations using breach-context wordlists
- Full S3 policy enumeration: policy, ACL, versioning, encryption, website, logging, lifecycle, object lock
- Cross-provider bucket takeover detection
- Shannon entropy analysis + 25-regex PII detection engine
- DNS CNAME resolution for dangling domain detection
- AWS SigV4 signing, presigned URL generation and testing
- GCP OAuth and Azure SAS authentication support
- Automatic risk classification: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Asyncio-based high-performance scanning engine
- CLI with granular feature toggles and JSON output
- Comprehensive test suite (24 tests)
- GitHub Actions CI/CD pipeline
