# Changelog — MikrotikAPI-BF

## [3.17.0] — 2026-09-26

### Added
- CVE-2026-67276: MikroTik RouterOS SSH RSA key-identity mismatch authentication bypass
  - Server performs modulus-only comparison → forged key with same modulus authenticates
  - Pruva.dev REPRO-2026-00365 verified reproduction
- MikroTick SSH Chain: username '-2' auth bypass (no password, no key)
  - Two chained SSH flaws enabling complete authentication bypass
  - Exploited before patches shipped (CERT Polska disclosure)

## [3.16.0] — 2026-09-24

### Added
- pywinbox_adapter.py: Winbox M2 protocol honeypot adapter (Nozomi Networks tricotools)
  - Captures all M2 login attempts with full session recording
  - Extracts credential patterns for threat intelligence

## [3.15.0] — 2026-09-19 (previous release)