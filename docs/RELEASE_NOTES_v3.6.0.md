# Release Notes v3.6.0

Author: André Henrique (LinkedIn/X: @mrhenrike)
Date: 2026-04-03

## Highlights
- New security test modules: SNMP, web security, SSH audit, hardening checks, privilege escalation, timing oracle (API/CLI), and offline artifact analyzer.
- New CLI capabilities in `mikrotikapi-bf.py` for standalone and orchestrated test execution.
- Hardening and lab automation scripts for CHR environments, including policy-based user/group provisioning.
- Updated banner and project identity to `MikrotikAPI-BF`.

## Security Validation Scope
- SNMP complete: community enum, OID read/write probes, MIB validation.
- Web security dedicated: headers/cookies/REST endpoint checks and auth behavior.
- Neighbor discovery matrix: LLDP/MNDP/CDP visibility.
- Entry vectors matrix by protocol and user profile.
- Timing side-channel feasibility analysis (char-by-char).

## Versioning
- Previous stable: `3.5.4`
- Current release: `3.6.0`

## Tag / Release Mapping
- Git tag target: `v3.6.0`
- GitHub release title: `MikrotikAPI-BF v3.6.0`

