# Security Policy

## Supported Version

This portfolio project currently supports the latest `main` branch.

## Reporting a Vulnerability

If you find a security issue, open a private advisory or contact the maintainer directly before publishing details.

## Security Practices

- Nmap XML uploads are parsed with network access and entity resolution disabled.
- Uploaded files are restricted by extension, size, and expected Nmap root element.
- Runtime artifacts are ignored by Git.
- The NVD integration uses timeouts and local fallback behavior.
- CI runs tests and a Bandit security scan.
