# Changelog

All notable changes to this skill are recorded here. Versions follow [semver](https://semver.org) and match `metadata.version` in `SKILL.md`.

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
