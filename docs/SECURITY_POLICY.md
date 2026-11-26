# Security Policy — Web Guard AI

## Authorization & Responsible Assessment
1. **Explicit Authorization Required**: Active domain assessments are blocked unless the target has passed ownership verification (`dns_txt` or `http_well_known`) or has a documented signed authorization record with defined scope.
2. **Non-Destructive Testing Only**: Web Guard AI performs passive reconnaissance, TLS/DNS inspection, security header/cookie/CORS evaluation, and safe read-only checks. It never runs exploit payloads, brute-force attacks, or denial-of-service probes.
3. **SSRF & DNS Rebinding Protection**: Every hostname is resolved prior to request dispatch; loopback, private RFC1918, link-local, multicast, carrier-grade NAT, and IPv6 ULA ranges are blocked. Redirect targets undergo the same validation on every hop.
4. **Static-Only Code Analysis**: Uploaded files, folders, ZIP archives, and cloned repositories are never imported or executed. Archive extraction enforces path-traversal (zip-slip) checks, file count caps, and maximum byte limits.
5. **Human-Controlled Remediation**: Source code patches require explicit approval, create pre-patch backups, and never modify remote live websites.
6. **Secret Management**: Credentials, JWT signing keys, and encryption keys must be supplied via environment variables and never committed to source control.
