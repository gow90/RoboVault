# RoboVault Security Documentation

**Version:** 2.1.0
**Author:** Gowtham Kuppudurai, QuantumScope
**Audience:** IT Security / InfoSec review

## TL;DR

RoboVault is a single-user desktop utility for backing up FANUC robot
controllers over FTP. It is not a web application, not a service, and has no
network-accessible attack surface of its own — it only makes outbound
connections (FTP to robots on the OT network, HTTPS to a user-configured
Teams webhook). The OWASP Top 10 is a web-app standard and does not apply
directly. The appropriate benchmark is **OWASP ASVS** (Application Security
Verification Standard).

This document maps RoboVault's controls to ASVS v4.0.3 and documents
deliberate design decisions where a control is intentionally out of scope.

---

## Architecture summary

```
┌─────────────────────┐        FTP (21)         ┌────────────────────┐
│                     │ ◄─────────────────────► │  FANUC R-30iB      │
│  RoboVault.exe      │     (OT network)        │  robot controller  │
│  (desktop, single   │                          └────────────────────┘
│   user, Tkinter)    │
│                     │        HTTPS             ┌────────────────────┐
│                     │ ─────────────────────►   │  Teams webhook     │
└─────────────────────┘     (corporate)           │  (Power Automate)  │
         │                                         └────────────────────┘
         │ read/write
         ▼
  %USERPROFILE%\...\
  robovault_config.json    (non-secret)
  robovault_config.secrets (DPAPI-encrypted, user-bound)
  RoboVault_Backups\...    (downloaded robot files)
```

- **Single user.** No login, no RBAC, no multi-tenancy. Everything runs
  in the Windows user session that launched the app.
- **Outbound only.** RoboVault listens on no ports.
- **No privilege escalation.** Runs as a standard user; no admin rights,
  no service install, no scheduled tasks.

---

## Threat model

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | Local attacker reads stored FTP passwords from disk | DPAPI encryption bound to the Windows user SID |
| T2 | Stolen config file exfiltrated off the machine | DPAPI ciphertext cannot be decrypted on any other machine or user account |
| T3 | Malicious filename from a compromised robot writes outside the backup directory (e.g. `..\..\Windows\System32\...`) | `safe_join_under()` with `Path.resolve()` boundary check on every write |
| T4 | Attacker substitutes a malicious Teams webhook URL in config to exfiltrate backup metadata | https-only validation; localhost/loopback rejected; URL stored encrypted |
| T5 | Other user on the same machine reads secrets sidecar | DPAPI is per-user; a second Windows user cannot decrypt |
| T6 | FTP traffic sniffed on the plant network | **Accepted risk.** FANUC R-30iB controllers do not support FTPS/SFTP. Mitigated by OT network segmentation (IT responsibility). See "Accepted risks" below. |
| T7 | Credential harvesting via memory dump | Out of scope — standard Windows process protection applies |
| T8 | Supply chain attack via dependencies | stdlib only. No `pip` packages. |

---

## ASVS v4.0.3 control mapping

### V1 – Architecture
- **V1.1.1** Secure SDLC — source code in git, manual review required for
  merges.
- **V1.4.1** Trust boundaries clearly identified: (1) FANUC FTP responses
  treated as untrusted input; (2) user-entered Teams URL validated before
  use.

### V2 – Authentication
- **V2.10.1 / V2.10.2** Service authentication credentials (FTP passwords,
  webhook URL) **encrypted at rest** via Windows DPAPI
  (`CryptProtectData`/`CryptUnprotectData`) with `CRYPTPROTECT_UI_FORBIDDEN`.
  Ciphertext is bound to the current Windows user account and cannot be
  decrypted by another user or on another machine.
- **V2.10.3** Secrets never appear in the public JSON config, in exports,
  or in log files.

### V5 – Validation, Sanitization & Encoding
- **V5.1.1** All settings are bounds-checked on load: `parallel_count`
  clamped to 1-10, `retention_days` clamped to 0-9999, `sched_days`
  filtered to integers 0-6.
- **V5.3.x** No SQL, no templating, no shell invocation with user input.
  `subprocess.run()` uses argv list form only.

### V6 – Stored Cryptography
- **V6.2.1 / V6.2.2** DPAPI (Windows built-in, FIPS 140-2 validated) used
  for confidentiality of stored credentials. No custom crypto. No
  hard-coded keys.

### V7 – Error Handling & Logging
- **V7.1.1** FTP passwords never logged. Logs contain filenames,
  connection messages, and error text but not authentication material.
- **V7.4.x** Exceptions caught at the engine boundary do not leak
  credentials into the UI log.

### V9 – Communications
- **V9.1.1** Teams webhook enforced HTTPS-only (`urllib.parse` scheme
  check rejects `http:`, `ftp:`, `file:`, `javascript:`, etc.).
  Localhost/loopback addresses rejected to prevent accidental exfil via
  local proxies.
- **V9.1.2** FTP-to-FANUC is **cleartext by design** — see "Accepted
  risks" section. The FANUC R-30iB controller family does not support
  FTPS or SFTP.

### V10 – Malicious Code
- **V10.3.x** No dynamic code execution (`eval`, `exec`, `__import__` with
  user input). No plugin loading. No remote code fetch.

### V12 – File and Resources
- **V12.3.1 / V12.3.3** Path traversal guards on every file write:
  `safe_join_under(base, *parts)` resolves the final path and verifies
  with `Path.relative_to()` that it stays inside `base`. A malicious
  filename from a compromised FTP server cannot escape the per-robot
  backup directory.
- **V12.4.1** Filenames containing `..`, absolute paths, and null bytes
  are neutralized by `sanitize_path()` before being joined.

### V13 – API and Web Service
- Not applicable. RoboVault exposes no API.

### V14 – Configuration
- **V14.1.1** Config file (`robovault_config.json`) contains no secrets.
- **V14.2.1** Stored secrets sidecar (`robovault_config.secrets`) is
  written atomically (tempfile + `os.replace`) with `0600` permissions on
  POSIX. On Windows, DPAPI user-binding is the primary control.
- **V14.4.1** Config exports deliberately exclude credentials — the
  export JSON contains a `_note` field informing the user that passwords
  and the webhook URL must be re-entered after import.

---

## Accepted risks

### A1 — Cleartext FTP to robots

**Risk:** FTP traffic between RoboVault and FANUC controllers is
unencrypted. A malicious actor with access to the OT network can observe
program file contents and (if non-anonymous login is used) FTP
credentials.

**Why accepted:**
1. FANUC R-30iB controller firmware does not support FTPS (explicit or
   implicit TLS) or SFTP. The protocol is dictated by the hardware.
2. Most deployments use blank/anonymous FTP credentials, so no credential
   is exposed in transit.
3. The OT network is segmented and not accessible from corporate /
   internet networks (QuantumScope IT responsibility, not RoboVault's).
4. Robot program files are not secrets — they are engineering artifacts
   already handled outside of RoboVault (RoboGuide, shared drives, etc.).

**Compensating controls:** OT network segmentation, VLAN isolation,
jump-host access for engineers.

### A2 — PyInstaller false positives on AV

**Risk:** Machine-learning-based AV engines (SentinelOne Static ML, Bkav
W64.AIDetectMalware, DeepInstinct, etc.) occasionally flag the
PyInstaller-packed `.exe` as suspicious. No signature-based engine
(Microsoft Defender, Kaspersky, ESET, etc.) flags the binary.

**Why this happens:** PyInstaller's `--onefile` bootloader unpacks the
embedded interpreter to `%TEMP%` at runtime, a pattern shared with some
dropper malware. ML classifiers trained on behavior heuristics fire on
the packer, not on RoboVault's code.

**Remediation path:**
- Submit as false positive to flagging vendors (standard process, usually
  whitelisted within days).
- Code-sign the executable with an Authenticode certificate (planned).
- Alternative: ship as `--onedir` build or as `.py` source + Python
  runtime on engineering workstations.

---

## Build & deployment

- Source: Python 3.10+, stdlib only.
- Package: `pyinstaller --onefile --windowed --name RoboVault robovault_portable.py`
- Config files are written next to the executable (or next to the script
  when run from source).
- Uninstall: delete the `.exe` and the `%USERPROFILE%\RoboVault_Backups\`
  folder. Nothing is written to the registry, no services are installed.

## Security contact

Gowtham Kuppudurai — QuantumScope Controls/Automation.
