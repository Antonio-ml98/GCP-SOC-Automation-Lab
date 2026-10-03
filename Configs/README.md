# Configuration Files

This directory contains sanitized configuration examples used in the GCP SOC Automation Lab.

The configurations demonstrate how the major components of the project were integrated while ensuring that credentials, API keys, passwords, tokens, public IP addresses, and other sensitive values are not exposed.

## Configuration Areas

- **Wazuh** — SIEM manager and endpoint agent configuration examples.
- **AI Analyzer** — Configuration and service files for the Vertex AI-powered SOC alert analyzer.
- **Automation** — Sanitized configuration examples related to Shuffle and TheHive integration.

## Security Notice

All configuration files in this repository are sanitized before publication.

Sensitive values are removed or replaced with placeholders such as:

- `<REDACTED>`
- `<YOUR_API_KEY>`
- `<PROJECT_ID>`
- `<PRIVATE_IP>`
- `<PUBLIC_IP>`

Original production/lab configuration files containing credentials or secrets are intentionally excluded from this public repository.
