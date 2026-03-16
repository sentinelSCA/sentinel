# Security Policy

## Reporting Vulnerabilities

If you discover a vulnerability in Sentinel, please report it privately.

Email:
sentinelsca@gmail.com

Please include:

- description of the issue
- steps to reproduce
- affected component
- possible impact

Do not open public GitHub issues for security vulnerabilities.

---

## Supported Versions

| Version | Supported |
|--------|-----------|
| main | Yes |

---

## Hardening Recommendations

For production deployments:

- protect the dashboard behind authentication
- rotate agent keys regularly
- run workers with minimal privileges
- use TLS for all traffic
- isolate Redis from public networks
