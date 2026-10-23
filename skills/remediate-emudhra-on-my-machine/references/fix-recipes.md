# Fix recipes for check failures

## Contents

- [How to use this file](#how-to-use-this-file)
- [Fixed versions](#fixed-versions)
- [Homebrew upgrades](#homebrew-upgrades)
- [Python](#python)
- [Lock files](#lock-files)
- [Node.js](#nodejs)
- [Git on Windows](#git-on-windows)
- [Go, uv, rustup, Deno, Homebrew](#go-uv-rustup-deno-homebrew)
- [Java](#java)
- [System trust store](#system-trust-store)
- [Operating system, browsers, and apps](#operating-system-browsers-and-apps)
- [Things never to do](#things-never-to-do)

## How to use this file

Each recipe is a **vetted recipe**: the exact command was reviewed as part of this skill. Label it that way when asking permission. Anything adapted beyond substituting the path or version shown is **improvised** and must be labeled as such.

Before running a recipe, record what it replaces (the old version or old setting) so the undo in the log is exact. After running it, append a line to the action log:

- macOS/Linux (works from bash or zsh): `bash -c '. "$1/scripts/lib.sh" && rem_log vetted-recipe "$2" "$3" "$4"' _ "$SKILL_DIR" "<action>" "<old -> new>" "<undo command>"`
- Windows (PowerShell): `. "$SKILL_DIR/scripts/lib.ps1"; Write-RemLog vetted-recipe "<action>" "<old -> new>" "<undo command>"`

`SKILL_DIR` is this skill's folder, the one that contains `SKILL.md`.

## Fixed versions

From <https://emudhra.we-have-a-problem.com/> and the vendors' own advisories, as of October 22, 2026. The site keeps adding fixed releases, so check it when a tool is not listed here.

| Component | Minimum fixed version |
|---|---|
| Python certifi | 2026.10.19 |
| pip | 26.2.2 (needs Python 3.10+). The check tests older pips live, because pip trusts its own bundled certificates alongside `PIP_CERT` and the system store |
| conda `ca-certificates` (per environment) | 2026.10.20 on the defaults channel, 2026.10.19 on conda-forge (none for Intel Macs on defaults) |
| conda | 26.9.4 |
| Node.js | 22.23.4, 24.22.1, or 26.12.1 (other release lines have no fix) |
| Go | 1.27.3 or 1.26.10 (programs built with older Go keep the old behavior) |
| uv | 0.13.4 rejects the test hosts; 0.13.5 also distrusts the compromised keys and ships fixed Pythons (recommended) |
| Rustup | 1.29.2 |
| Deno | 2.9.8 |
| Bun | 1.4.4 |
| mise | 2026.10.17 |
| pixi | 0.82.1 |
| Git for Windows | 2.56.0.windows.3 |
| Homebrew ca-certificates | 2026-09-25_1 |
| Homebrew certifi | 2026.10.19 |
| MacPorts curl-ca-bundle | 8.23.0_1 (also used by MacPorts git) |
| Java | 27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, or 8u511 (Oracle and OpenJDK), and Azul's fixed builds. See Java below for which vendors have shipped |
| CPython | 3.15.1, 3.14.9, or 3.13.17 (they only update the pip that ships with Python; the check warns on older releases of those lines) |
| Electron | 45.0.0, 44.9.1, 43.8.1, or 42.11.16 (apps update themselves; Slack 4.52.182 ships 44.9.1) |
| Firefox | 158.0.1, or ESR 153.5.1 or 115.43.1 (Android 158.0.2). OneCRL protects older versions without an update, so the check WARNs instead of FAILing |
| Docker Desktop | 4.96.3 (Docker ships its fix in batches; install each patch release) |
| Claude Code | 2.1.303 |
| cloudflared | 2026.10.2 (Cloudflare WARP: 2026.8.2115.0) |
| Azure CLI | no fixed release yet (it bundles an old certifi) |

Linux distribution packages (the admin script installs these first, then checks the store):

| Distribution | Fixed `ca-certificates` |
|---|---|
| Debian 12 / 13 / unstable | 20250419~deb12u2 / 20250419+deb13u1 / 20260816+nmu1 |
| Ubuntu 22.04 / 24.04 / 26.04 / 26.10 | 20260816ubuntu0.22.04.1 / .24.04.1 / .26.04.1 / .26.10.1 (USN-8944-1) |
| Fedora | 2026.2.92_v9.0.319 |
| RHEL 9 / 10 | 2026.2.92_v9.0.319-90.3.el9_8 (RHSA-2026:88459) / 2026.2.92_v9.0.319-100.3.el10_2 (RHSA-2026:88455) |
| Oracle Linux 8 / 9 / 10 | 2025.2.80_v9.0.304-80.2.0.1.el8_10 / 2025.2.80_v9.0.305-91.0.1.el9 / 2025.2.80_v9.0.305-102.0.1.el10_2 (numbered below Fedora's, but fixed) |
| RHEL 8, Alma, Rocky, Amazon Linux | pending; the admin script's workaround applies |
| Arch `ca-certificates-mozilla` | 3.131.1-1 |
| Alpine | 20261020-r0 (the admin script does not support Alpine; use the site's commands) |
| NixOS `cacert` | 3.131.1 is in nixpkgs master only, not yet in a channel, so the `configuration.nix` change is the fix |

Operating systems and phones:

- **Apple** has blocked the certificates since October 22, through background trust data rather than an OS release, so there is no macOS or iOS version to install for it. Its block on the six emSign chains also depends on eMudhra's OCSP server answering, and it failed open while that server was down on October 21 and 22. That is why the macOS admin script's keychain step matters even after Apple's block. A separate Apple certificate fix ([CVE-2026-86881](https://app.opencve.io/cve/CVE-2026-86881)) shipped in macOS 15.8, 26.7, and 27 and iOS 26.7 and 27, so keep recommending those.
- **Microsoft** has blocked them since October 20 through Windows' automatic untrusted-certificate list. There is no KB, and the block does not show in `certlm.msc`; the check reports when Windows last synced that list.
- **Google** blocked them in Chrome on October 17 (CRLSet, no update needed) and on Android through Google Play Services on October 19; restarting the phone applies it ([Google](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)). Chrome also removes emSign ECC Root CA - G3 on October 27, which is expected to break some legitimate emSign sites in Chrome.
- **Mozilla** blocked them in Firefox through OneCRL on October 17; the fixed versions are in the table.

## Homebrew upgrades

Every Homebrew recipe in this file runs `brew upgrade` the same way. Without these two settings it upgrades every installed formula that depends on the one named, which for `ca-certificates` and the Pythons can be dozens of unrelated tools (Node, Deno, a new Python, ffmpeg).

1. Preview first, with the same variable as the real run, and include the list in the request: `HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade --dry-run <formulae>`. If it would upgrade anything beyond the named formulae and their own dependencies, say so.
2. Run: `HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade <formulae>`. The first variable keeps the old keg so it can be restored; the second stops the dependents sweep.

Undo: `brew unlink <formula>`, then `brew link` the old keg path under `$(brew --cellar)/<formula>/`; describe this rather than promising a one-liner. If Homebrew doesn't offer the fixed version yet (`brew info <formula>`), report it as open and re-check later; don't move the user to a different installer unless they ask.

## Python

**A plain interpreter or virtualenv (pyenv, python.org, a project `.venv`, including uv-created ones):** vetted script.

```bash
bash "$SKILL_DIR/scripts/fix-python-env.sh" /path/to/python
```

Windows: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$SKILL_DIR/scripts/fix-python-env.ps1" -Python C:\path\to\python.exe`

It logs its own undo. It also handles uv-created virtualenvs, which have no pip, by upgrading certifi with `uv pip`. Exit code 3 means it deliberately skipped the interpreter and printed the right command instead; offer that command as a vetted recipe (never one that needs sudo). Exit code 4 means the environment is still vulnerable and could not be fixed; report it as open. In a conda environment, exit 3 can follow a partial pip upgrade: the action log records what pip changed, and the printed conda command covers the rest. On Python 3.9 or older, exit 4 can follow a logged certifi upgrade: certifi is fixed, and pip stays open because the fixed pip needs Python 3.10.

**Homebrew Python:** follow [Homebrew upgrades](#homebrew-upgrades) with the formulae `fix-python-env.sh` prints. pip comes with `python@3.X`. If another formula (such as `oci-cli` or `semgrep`) installed Homebrew's `certifi` formula, Homebrew's Pythons import that one, and upgrading `python@3.X` does not upgrade it; the check reports it as `homebrew|certifi`.

**conda environments** (base and named, including mamba and micromamba): run the vetted fix script on the environment's python, like any other interpreter. It upgrades each package with whatever installed the copy Python actually imports, read from that package's `INSTALLER` file (a `conda-meta/` record alone can be stale after pip replaced the package):

- **Installed by pip** (common in older environments): upgraded with the environment's own pip, and logged with an undo.
- **conda's own `ca-certificates` package:** conda's OpenSSL, and Python's `ssl` module in a conda environment, read the environment's `ssl/cacert.pem` (`Library\ssl\cacert.pem` on Windows), which comes from this package rather than from certifi. Updating `base` does not update other environments. The script adds `'ca-certificates>=2026.10.20'` (defaults) or `'ca-certificates>=2026.10.19'` (conda-forge) to the conda command when it's older. Anaconda's defaults channel has no fixed build for Intel Macs (osx-64); the script reports that as open.
- **Installed by conda:** left alone. The script prints `conda install -p <env prefix> 'ca-certificates>=...' 'certifi>=2026.10.19' 'python=<X.Y>'` (with whichever of `ca-certificates`, certifi, and `'pip>=26.2.2'` are needed) and exits 3. On micromamba-only machines it names `micromamba` (or `mamba`) instead of `conda`. The Python pin keeps conda from upgrading the interpreter to satisfy the request, and a conda-forge environment also gets `-c conda-forge`; offer that as a vetted recipe. It uses `conda install` with a minimum version because that fails loudly if the channel can't provide it, while `conda update` can report success and change nothing. Undo: `conda install -p <env prefix> certifi=<old> ca-certificates=<old>`, with `pip=<old>` if pip was upgraded.
- **conda-owned certifi on an older Python:** conda's builds of the fixed certifi need Python 3.10 or later on the defaults channel and 3.11 or later on conda-forge (the default for miniforge, mambaforge, and micromamba), so conda cannot install it below that. The script still prints the conda command for what can be fixed (`ca-certificates` has no Python requirement), then a FAIL line for certifi, and exits 4. Offer the command, record certifi as open, and suggest retiring the environment or rebuilding it on Python 3.10 or later.

**uv-managed Python:** `uv python upgrade 3.X`. Undo: `uv python install 3.X.Y` for the old patch version.

**Project virtualenvs.** Find candidates without running any Python (fast, read-only). It searches the same project folders as the check (honoring `REMEDIATE_EMUDHRA_PROJECTS`), runs from bash or zsh, including Git Bash on Windows, and matches both the `lib/python3.X/site-packages` and the Windows `Lib\site-packages` layouts:

```bash
bash -c '. "$1/scripts/lib.sh"; rem_project_dirs | while read -r p; do find "$p" -maxdepth 4 -name pyvenv.cfg 2>/dev/null; done |
  while read -r cfg; do d="$(dirname "$cfg")"; find "$d" -maxdepth 4 -type d -path "*site-packages/certifi-*.dist-info" 2>/dev/null | sed "s|^|$d |"; done' _ "$SKILL_DIR"
```

Only virtualenvs whose `certifi-*.dist-info` is older than 2026.10.19 need the fix. Show the full list, then ask once to run the fix script on exactly those, as one action. The interpreter is `<venv>/bin/python` on macOS and Linux and `<venv>\Scripts\python.exe` on Windows (pass that to `fix-python-env.ps1 -Python`). Skip virtualenvs the user does not recognize or that belong to a repository they don't work on. If the repository's `uv.lock` pins an old certifi, the next `uv sync` puts it back; see [Lock files](#lock-files).

**Tool environments** (`pipx` and `uv tool`): each installed tool has its own virtualenv with its own pip and certifi, wherever `pipx environment --value PIPX_LOCAL_VENVS` and `uv tool dir` say (defaults: `~/.local/share/pipx/venvs/` on Linux, `~/Library/Application Support/pipx/venvs/` on macOS, `%LOCALAPPDATA%\pipx\pipx\venvs\` on Windows; uv: `~/.local/share/uv/tools/`, or `%APPDATA%\uv\data\tools\`). pipx tool environments have no pip of their own: they share one in pipx's `shared` folder, which the check reports as `pipx's shared pip`. The check lists the vulnerable ones as `tool environment` FAILs; fix each with the fix script on that environment's python (`<venv>/bin/python`, or `<venv>\Scripts\python.exe`). `uv tool upgrade <tool>` or `pipx upgrade <tool>` upgrade only the tool, not necessarily certifi. Old `virtualenv` releases (before 21.14.12) also put the vulnerable pip into new environments; upgrade virtualenv itself if the user creates environments with it.

**Why pip is tested live:** pip trusts its own bundled certificates in addition to `PIP_CERT`, `--cert`, and the system store, so a pip older than 26.2.2 can trust the compromised chains even on a machine whose system store is fixed. The check therefore tests each such pip against the test hosts. Apple's `/usr/bin/python3` pip passes once the macOS admin script has run.

**End-of-life Python (3.9 and older):** the fixed pip cannot run there. Offer to upgrade `certifi` only, and recommend removing the interpreter if unused (`pyenv uninstall 3.9.X`). Removal is not reversible without reinstalling, so ask separately and never bundle it with other actions.

**python.org Python that "cannot verify any site":** not an exposure. Mention that running `/Applications/Python 3.X/Install Certificates.command` installs certifi for it, and treat it as optional.

**OS-owned Python** (Apple's `/usr/bin/python3`, or `/usr/bin/python3` on Linux): never modify the interpreter or the packages it shipped with. Its pip uses the system trust store, which the admin script fixes (on macOS by pointing pip at the fixed `/etc/ssl/cert.pem`). A Linux distribution's own certifi uses the system store too and reports PASS. Apple's python3 ships no certifi at all, so a certifi the check finds there was added by someone:

- `FAIL ... certifi ... in your user site-packages`: installed with `pip install --user`, so it is the user's to upgrade. Recipe: `/usr/bin/python3 -m pip install --user --upgrade 'certifi>=2026.10.19'`. Undo: `/usr/bin/python3 -m pip install --user certifi==<old>`. If pip refuses with `externally-managed-environment`, stop and report it as open; never add `--break-system-packages`.
- `FAIL ... certifi ... in <dir> was added by ...`: `<dir>` is the site directory it was found in, somewhere else on `sys.path`. If `<dir>` is a `PYTHONPATH` entry the user set, upgrade it there (`/usr/bin/python3 -m pip install --target <dir> --upgrade 'certifi>=2026.10.19'`, **Improvised**). In any other place (`/Library/Python/3.X/site-packages` from an old `sudo pip`, or Apple's own site-packages inside Xcode or the Command Line Tools), report it as open: those belong to the OS install, and some need sudo, which the agent never runs. A `--user` install does not help either, because Apple's python3 searches its own site-packages before the user site.
- `WARN ... certifi ... shipped with this OS-owned Python`: a copy the OS itself installed. Not a fix to attempt. Only scripts that use `requests` with this interpreter are affected; suggest running those with a pyenv, uv, or Homebrew Python, and report it as open with that reason.

## Lock files

`WARN|lockfile|uv.lock` means repositories in the scanned project folders pin certifi older than 2026.10.19 in `uv.lock`. The list file named in the line has one `<version> <repository>` per line. Until the pin is bumped, `uv sync` reverts the virtualenv fix, and any image built from the repository ships the old certifi.

Bumping a pin changes a tracked file, so it belongs to that repository's own workflow (branch, commit, PR). Offer it per repository the user works on, and report the rest as open; don't sweep every repository on the machine. Do this only after `uv` itself PASSes, since `uv lock` downloads from the package index.

Recipe, one action per repository: back up `uv.lock` to the backups folder, then run `uv lock --upgrade-package certifi` in the repository. It upgrades certifi and leaves the other pins alone. Undo: `cp <backup> <repo>/uv.lock`. The virtualenv itself was already fixed by the fix script, so no `uv sync` is needed; if the user wants one later, it is a separate action. Don't commit or push for the user unless they ask. If the new lock still resolves an older certifi, `pyproject.toml` caps it; report that as open.

## Node.js

Install the fixed release on the same line (22, 24, or 26), make it the default, and leave old versions installed until the user decides. A project's `.nvmrc` may pin an old version; check `bash -c '. "$1/scripts/lib.sh"; rem_project_dirs | while IFS= read -r d; do find "$d" -maxdepth 3 -name .nvmrc; done' _ "<SKILL_DIR>"` before suggesting removal.

| Manager | Command | Undo |
|---|---|---|
| nvm (macOS/Linux) | `nvm install 24.22.1 && nvm alias default 24.22.1` (new terminals get it; the agent keeps its old PATH until restarted, which the check reports as `INFO\|node\|PATH`) | `nvm alias default <old>` |
| nvm-windows | `nvm install 24.22.1; nvm use 24.22.1` | `nvm use <old>` |
| fnm | `fnm install 24.22.1 && fnm default 24.22.1` | `fnm default <old>` |
| Volta | `volta install node@24.22.1` | `volta install node@<old>` |
| Homebrew | [Homebrew upgrades](#homebrew-upgrades) with `node` | Old keg kept; relink it |
| Windows installer | Download the LTS installer from <https://nodejs.org/> (the user runs it) | Reinstall the old version |

To remove an old version later, ask separately: `nvm uninstall <old>`. Never remove a version a `.nvmrc` pins without the user's explicit agreement.

## Git on Windows

Git for Windows 2.56.0.windows.3 (October 22) is a security release for this incident; upgrading to it (or later) from <https://gitforwindows.org/> is the fix, and the user runs the installer. Without an upgrade, older Git for Windows uses its own bundled CA file, which predates the fix; switch it to the Windows store, which carries Microsoft's block:

```powershell
git config --global --get http.sslBackend   # record the old value first
git config --global http.sslBackend schannel
```

Undo: `git config --global http.sslBackend <old>`, or `git config --global --unset http.sslBackend` if there was none. On macOS and Linux, git uses the system store; the admin script covers it.

## Go, uv, rustup, Deno, Homebrew

| Tool | Command | Undo |
|---|---|---|
| Go (Homebrew) | [Homebrew upgrades](#homebrew-upgrades) with `go` | Old keg kept; relink it |
| Go (Windows) | `winget upgrade --id GoLang.Go` | Reinstall the old version |
| Go (official installer) | Download from <https://go.dev/dl/> (the user runs it) | Reinstall the old version |
| uv (standalone) | `uv self update` (to 0.13.5 or later), then `uv python upgrade` for uv's own Pythons. Existing virtualenvs keep their pip; fix those with the fix script | `uv self update <old>` |
| uv (Homebrew) | [Homebrew upgrades](#homebrew-upgrades) with `uv` | Old keg kept; relink it |
| rustup | `rustup self update` | None needed |
| Deno | `deno upgrade` | `deno upgrade --version <old>` |
| Homebrew CA bundle | [Homebrew upgrades](#homebrew-upgrades) with `ca-certificates` | Old keg kept; relink it |
| Homebrew certifi | [Homebrew upgrades](#homebrew-upgrades) with `certifi` | Old keg kept; relink it |
| cloudflared | `brew upgrade cloudflared` per [Homebrew upgrades](#homebrew-upgrades), the OS package manager, or Cloudflare's installer (the user runs it) | Reinstall the old version |
| MacPorts curl-ca-bundle | `sudo port selfupdate && sudo port upgrade curl-ca-bundle` (the user runs it; it needs their password) | `sudo port activate curl-ca-bundle @<old>` |

## Java

Fixed releases: 27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, and 8u511 from Oracle and OpenJDK ([OpenJDK advisory, CVE-2026-91403](https://openjdk.org/groups/vulnerability/advisories/2026-10-21), [Oracle](https://ops.java/emudhra)), and Azul's fixed builds. A patched JDK blocks the compromised intermediates in `lib/security/blocked.certs` (`blacklisted.certs` on JDK 8) and keeps the roots in `cacerts`.

Not every vendor has shipped yet (as of October 22): **Temurin (Adoptium) and Amazon Corretto have no fixed builds**, and of Homebrew's JDKs only `openjdk@17`, `openjdk@21`, and `openjdk@25` are fixed (`openjdk` 27.0.1, `openjdk@11`, and `openjdk@8` are not). JDKs from Debian, Ubuntu, Fedora, RHEL, Oracle Linux, Arch, and Gentoo use the OS certificate store, so the OS's `ca-certificates` fix covers them.

The check tests each JDK live against the test hosts when it can (JDK 11 or later, with network access). Otherwise it treats a JDK as safe when `blocked.certs` lists all 16 compromised intermediates, or when `cacerts` no longer has the two affected roots.

For a FAIL, **upgrading to a fixed build from a vendor that has one is the preferred fix**: Homebrew `openjdk@17`, `@21`, or `@25`, the Oracle or Azul installers, or the OS package manager. The user runs installers themselves. Don't suggest a Temurin or Corretto upgrade as a fix until those vendors ship. Until then, the admin script for each OS removes the two affected roots from that JDK's `cacerts`, backing the file up first; it leaves patched JDKs alone. OpenJDK's own interim fix replaces `blocked.certs` with the file from ops.java; prefer the admin script, whose change is pinned and logged here.

## System trust store

Never edit the system trust store directly. Use the admin script for the OS, which the user runs in their own terminal (step 4 of the workflow):

| OS | Script |
|---|---|
| macOS | `scripts/admin-fix-macos.sh` |
| Windows | `scripts/admin-fix-windows.ps1` |
| Debian, Ubuntu, Pop!_OS, Mint | `scripts/admin-fix-linux.sh` |
| Fedora, RHEL, CentOS Stream, Rocky, Alma, Amazon Linux | `scripts/admin-fix-linux.sh` |
| Arch and Arch-based | `scripts/admin-fix-linux.sh` (runs a full `pacman -Syu`, since Arch does not support partial upgrades) |
| NixOS | `scripts/admin-fix-linux.sh` (prints the configuration change; changes nothing itself) |

A macOS update rewrites `/etc/ssl/cert.pem` and brings the two roots back. Run the admin script after the macOS update, not before; if the update comes later, run it again afterwards.

Side effects and limits to mention:

- **macOS:** after the `cert.pem` step, Apple's `/usr/bin/perl` (HTTP::Tiny has no keychain fallback) can no longer reach sites that chain through the AAA cross-sign, such as example.com; this is expected. On Macs with full Xcode selected, macOS can refuse the `sitecustomize.py` step inside Xcode.app; the script then prints a `pip config` alternative and carries on. nix-darwin users also need the NixOS change.
- **Fedora/RHEL family:** the site's p11-kit blocklist, which the script applies, leaves the two roots usable for unspecified purposes in `/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt` (an open site issue). Prefer the distribution's fixed package where it exists (RHEL 9 and 10, Oracle Linux 8 to 10).
- **Debian/Ubuntu:** after the workaround, the script also rebuilds the Java store from `ca-certificates-java` when that package is installed, as the site advises.
- **Alpine, openSUSE/SLES:** not supported by the script; record the store as open and point to the site's commands.

## Operating system, browsers, and apps

These cannot be done from the agent. Give the user the steps:

- **macOS:** System Settings > General > Software Update. Install the update and restart, then run the check again: the update restores `/etc/ssl/cert.pem`, so the admin script usually needs another run.
- **Windows:** Settings > Windows Update > Check for updates. Install and restart.
- **Linux:** install all pending updates with the distribution's updater (Software Updater, GNOME Software, `apt`, `dnf`, or `pacman -Syu`) and reboot if it asks.
- **Browsers:** Chrome and Edge: menu > Help > About, then Relaunch. Firefox: Help > About Firefox (158.0.1, or ESR 153.5.1 or 115.43.1). Safari uses Apple's system check.
- **Apps:** update Slack (4.52.182 or later), Zoom, VS Code, 1Password, Docker Desktop (4.96.3 or later, and each patch after it), Cloudflare WARP (2026.8.2115.0), and Claude Desktop from their own update menus.
- **iPhone and iPad:** there is no user-side fix. Apple's block arrives as background trust data, not in an iOS release: keep Settings > General > Software Update > Automatic Updates > "Security Responses & System Files" on, and still install iOS 26.7 or 27 for the separate certificate fix. Open the test URLs in Safari to confirm.
- **Android:** restart the phone so the Google Play Services update applies.

## Things never to do

- Disable TLS verification anywhere (`verify=False`, `-k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY`, `http.sslVerify false`), even "temporarily" to get past an error.
- Run `sudo`, or an elevated PowerShell, from inside the agent.
- Remove roots from Windows Trusted Root Certification Authorities. Microsoft's automatic updates re-add them, and doing so breaks legitimate sites.
- Use `pip install --break-system-packages`, or upgrade the packages that shipped with Apple's `/usr/bin/python3` (a certifi the user added to their user site or a `PYTHONPATH` entry is the exception; see OS-owned Python).
- Kill processes by name or pattern.
- Uninstall anything, or change organization-managed settings or policies, without a separate, explicit request from the user.
