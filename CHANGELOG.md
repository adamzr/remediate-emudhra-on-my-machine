# Changelog

All notable changes to this skill are recorded here. Versions follow [semver](https://semver.org) and match `metadata.version` in `SKILL.md`.

## 1.2.1 (October 22, 2026)

- The read-only check no longer runs pipx to find tool environments, because even `pipx environment` writes log files. It reads `PIPX_HOME`, `PIPX_SHARED_LIBS`, and `uv tool dir` instead, with the usual defaults, and resolves each folder once, so no environment is reported twice.
- In conda environments, the fix script no longer prints "Nothing for pip to upgrade" right before the conda command.

## 1.2.0 (October 22, 2026)

Follows the incident site, vendor advisories, and distribution errata as of October 22.

- **pip is tested live.** pip trusts its own bundled certificates alongside `PIP_CERT` and the system store; on a Linux machine with a fixed store, pip 25.2 still trusted the compromised chain. The check had reported such pips as PASS ("uses the system trust store"); it now tests each pip older than 26.2.2 against the test hosts.
- **conda's `ca-certificates` package**, which conda's OpenSSL and Python's `ssl` module read, is checked per environment and included in the conda command (2026.10.20 on defaults, 2026.10.19 on conda-forge; none for Intel Macs on defaults). Environments too old for the fixed certifi still get the command for what can be fixed, then exit 4.
- **macOS admin script:** a refused `sitecustomize.py` write inside Xcode.app (macOS App Management) no longer stops the keychain and JDK steps; the script prints a `pip config` alternative.
- **Debian/Ubuntu admin script:** rebuilds the `ca-certificates-java` store after the workaround, as the site now advises.
- **New checks:** pipx and `uv tool` environments (and pipx's shared pip), the MacPorts CA bundle, cloudflared 2026.10.2, Azure CLI (no fix yet), Firefox 158.0.1 / ESR 153.5.1 / 115.43.1 (a WARN, since OneCRL protects older versions), and on Windows the date of the last untrusted-certificate-list sync. uv 0.13.4 is now a WARN recommending 0.13.5.
- **Live tests:** curl and Python's urllib count a connection as trusted only when the test site's own reply comes back, so a TLS-intercepting proxy reads as inconclusive instead of FAIL. The pip test counts it as trusted only when pip logs a real HTTP response, and as rejected only on a certificate verification error.
- **Corrected facts:** Docker Desktop 4.96.3 (fix shipping in batches), Git for Windows 2.56.0.windows.3, which JDK vendors have shipped, Apple's block (background trust data, OCSP-dependent; nothing to install on iPhone), Android's date (October 19), Chrome's October 27 root removal, and a distribution table (Debian, Ubuntu, RHEL 9/10, Oracle Linux, Alpine). The rpm INFO line no longer calls Oracle Linux's fixed package unfixed, and NixOS's `cacert` is noted as master-only.
- **Fixes:** a conda-owned pip on Python 3.9 or older now exits 4 instead of 0; micromamba-only machines get a `micromamba` command; the fix script no longer runs Apple's `/usr/bin/python3` when the Command Line Tools are missing.

## 1.1.1 (October 22, 2026)

No behavior changes.

- Shell scripts are formatted with shfmt (settings in `.editorconfig`); CI checks formatting, Markdown (markdownlint), workflows (actionlint), and PowerShell at warning level (PSScriptAnalyzer).
- `tools/lint.sh` runs the same checks locally, and `tools/validate_skill.py --since` enforces a version bump and a CHANGELOG entry for changes to the skill.

## 1.1.0 (October 22, 2026)

The incident site now lists fixed releases for Java, Bun, and more tools; this release follows it.

- **Java:** patched JDKs (27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511) block the intermediates in `blocked.certs` and keep the roots in `cacerts`. The check now tests each JDK live (JDK 11 and later), falls back to `blocked.certs` and `cacerts`, and recommends the upgrade; the admin scripts leave patched JDKs alone.
- **New version checks:** Bun 1.4.4, conda 26.9.4, mise 2026.10.17, pixi 0.82.1, Claude Code 2.1.303, and a warning for CPython releases older than 3.13.17, 3.14.9, and 3.15.1. The Windows check now covers rustup, Deno, and Bun as well.
- **Browsers:** the two new test hosts whose chains were never logged to Certificate Transparency.
- **Fixes:**
  - Virtualenvs created from the OS Python were refused as OS-owned.
  - A bash 3.2 syntax error in `fix-python-env.sh`.
  - `fix-python-env` exits 4 when pip stays vulnerable on Python 3.9 or older, and when `uv` fails.
  - `REMEDIATE_EMUDHRA_PROJECTS` works under Git Bash.
  - macOS `cert.pem` is also checked by fingerprint, and the macOS admin script verifies its certificate files against the pins.
  - The read-only check no longer writes `.pyc` files.
- Apple's block is dated October 22, per the incident site.

## 1.0.0 (October 22, 2026)

First public release.

- Read-only check of the system trust store, curl, git, every Python with its pip and certifi, Node.js, Java, Go, uv, rustup, Deno, Bun, Homebrew, WSL distributions, project virtualenvs, and `uv.lock` pins.
- User-level fixes for Python environments, with backups and an undo log. In conda environments, each package is upgraded with the tool that installed it (conda or pip).
- Admin scripts for macOS, Windows, Debian/Ubuntu, Fedora/RHEL, and Arch, and printed instructions for NixOS.
- Install with `npx skills add adamzr/remediate-emudhra-on-my-machine`.
