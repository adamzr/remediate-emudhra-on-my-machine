# Changelog

All notable changes to this skill are recorded here. Versions follow [semver](https://semver.org) and match `metadata.version` in `SKILL.md`.

## 1.0.0 (October 22, 2026)

First public release.

- Read-only check of the system trust store, curl, git, every Python with its pip and certifi, Node.js, Java, Go, uv, rustup, Deno, Bun, Homebrew, WSL distributions, project virtualenvs, and `uv.lock` pins.
- User-level fixes for Python environments, with backups and an undo log. In conda environments, each package is upgraded with the tool that installed it (conda or pip).
- Admin scripts for macOS, Windows, Debian/Ubuntu, Fedora/RHEL, and Arch, and printed instructions for NixOS.
- Install with `npx skills add adamzr/remediate-emudhra-on-my-machine`.
