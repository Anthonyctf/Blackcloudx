<div align="center">

<pre>
██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗██╗      ██████╗ ██╗   ██╗██████╗ 
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
██████╔╝██║     ███████║██║     █████╔╝ ██║     ██║     ██║   ██║██║   ██║██║  ██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║     ██║     ██║   ██║██║   ██║██║  ██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝
</pre>

**Expert-Tier Multi-Cloud Storage Bucket Scanner**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/valley/blackcloud/actions/workflows/ci.yml/badge.svg)](https://github.com/valley/blackcloud/actions)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

</div>

---

## What is BlackCloud?

BlackCloud is a bleeding-edge reconnaissance tool designed for security professionals to hunt exposed cloud storage across **AWS S3**, **Google Cloud Storage**, and **Azure Blob Storage**. It goes far beyond simple bucket enumeration, offering deep policy analysis, content intelligence, takeover detection, and authenticated bypass testing.

Whether you are doing bug bounty hunting, red team engagements, or cloud security assessments, BlackCloud gives you the visibility others miss.

---

## Features

| Capability | Description |
|------------|-------------|
| **Multi-Cloud** | AWS S3 (31 regions), GCP, Azure — one tool, all providers |
| **Adaptive Rate Limiting** | Token-bucket algorithm with congestion backoff. Scans fast without getting blocked |
| **Smart Permutations** | 100+ breach-context naming patterns per base name |
| **Deep S3 Policy Enum** | Policy, ACL, versioning, encryption, website, logging, lifecycle, object lock |
| **Takeover Detection** | Identifies dangling CNAMEs and deleted buckets across all 3 providers |
| **PII & Secret Detection** | 25 regex patterns for keys, tokens, DB URLs, JWTs, private keys |
| **Entropy Analysis** | Shannon entropy scoring to find obfuscated secrets in listings |
| **Authenticated Testing** | AWS SigV4, presigned URL validation, GCP OAuth, Azure SAS |
| **DNS Recon** | Async CNAME resolution to find dangling domain mappings |
| **Risk Scoring** | Automatic CRITICAL / HIGH / MEDIUM / LOW / INFO classification |

---

## Architecture

```
Input Domain(s)
       |
       v
[ Permutation Engine ] ---> 100+ naming variants
       |
       v
[ Async Scanner ] --------> AWS (31 regions) + GCP + Azure
       |
       +---> [ Rate Limiter ] ----> Congestion-aware throttling
       +---> [ DNS Resolver ] ----> CNAME detection
       +---> [ Auth Layer ] ------> SigV4 / OAuth / SAS
       |
       v
[ Analysis Engine ]
       |
       +---> PII Detection (25 regexes)
       +---> Entropy Scoring (Shannon)
       +---> Sensitive File Matching (50+ extensions)
       +---> Policy Enumeration (S3 deep dive)
       +---> Takeover Detection
       |
       v
[ Risk Classifier ] -------> CRITICAL / HIGH / MEDIUM / LOW / INFO
       |
       v
   JSON / CLI Output
```

---

## Installation

ComingSoon101010101
Updating 

---

## Quick Start

```bash
# Basic scan against a domain
blackcloud -d example.com

# Scan all AWS regions + GCP
blackcloud -d example.com -p aws gcp --all-regions

# Authenticated scan with stealth mode
blackcloud -d example.com -k AKIA... SECRET... --stealth

# High-performance scan with JSON output
blackcloud -d example.com -o results.json --workers 100
```

---

## CLI Reference

```
blackcloud [-h] -d DOMAIN [-p PROVIDERS ...] [-w WORKERS] [-t TIMEOUT]
           [--all-regions] [--no-permutations] [--stealth]
           [--no-content-analysis] [--no-dns] [--no-policy]
           [--no-presigned] [--no-takeover] [--no-entropy]
           [--no-rate-limit] [-k ACCESS_KEY SECRET_KEY]
           [--gcp-token GCP_TOKEN] [--azure-sas AZURE_SAS]
           [--proxy PROXY] [-o OUTPUT] [--wordlist WORDLIST]
           [-v] [--version]
```

| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain or bucket name |
| `-p, --providers` | Cloud providers to scan (default: aws gcp azure) |
| `-w, --workers` | Max concurrent workers (default: 50) |
| `-t, --timeout` | Request timeout in seconds (default: 15) |
| `--all-regions` | Scan all 32 AWS regions |
| `--no-permutations` | Disable naming permutations |
| `--stealth` | Enable stealth mode (slower, randomized UAs) |
| `-k, --aws-keys` | AWS credentials for authenticated tests |
| `--gcp-token` | GCP OAuth token |
| `--azure-sas` | Azure SAS token |
| `--proxy` | HTTP proxy (http://host:port) |
| `-o, --output` | Output file for JSON results |
| `-v, --verbose` | Verbose output |

---

## Advanced Usage

### Bug Bounty Recon

```bash
# Aggressive scan with all features enabled
blackcloud -d target.com \
  --all-regions \
  --workers 200 \
  -o target_recon.json \
  -v
```

### Red Team Stealth Scan

```bash
# Slow, randomized, hard to detect
blackcloud -d victim.com \
  --stealth \
  --workers 5 \
  --no-dns \
  -p aws \
  -k AKIA... SECRET...
```

### Custom Wordlist

```bash
# Bring your own permutations
blackcloud -d corp.com --wordlist custom_buckets.txt --no-permutations
```

### Programmatic Usage

```python
import asyncio
from blackcloud import CloudBucketScanner, ScanConfig

config = ScanConfig(
    domains=["example.com"],
    providers=["aws", "gcp"],
    all_regions=True,
    aws_keys=("AKIA...", "SECRET..."),
)

async def scan():
    async with CloudBucketScanner(config) as scanner:
        results = await scanner.scan_all()
        for r in results:
            if r.exposure == "CRITICAL":
                print(f"CRITICAL: {r.bucket} -> {r.url}")

asyncio.run(scan())
```

---

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Format code
make format

# Build distribution
make dist
```

---

## Roadmap

- [ ] Passive discovery via Shodan / Censys / CRT.sh
- [ ] Web dashboard for result visualization
- [ ] Slack / Discord webhook alerting
- [ ] Automatic bucket takeover PoC generation
- [ ] Distributed scanning mode
- [ ] GitHub Action for CI/CD pipeline scanning

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) - Valley
