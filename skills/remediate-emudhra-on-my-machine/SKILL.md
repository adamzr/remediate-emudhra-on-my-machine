---
name: remediate-emudhra-on-my-machine
description: >-
  Checks whether this computer still trusts the compromised eMudhra certificate chains from the October 2026
  incident, and removes that trust everywhere it can. Covers the system trust store, curl, git, every Python
  with its pip and certifi, Node.js, Java, Go, uv, rustup, Deno, Homebrew, WSL distributions, and lock files,
  on macOS, Windows, and Linux (Debian/Ubuntu, Fedora/RHEL, Arch, NixOS). Fixes what needs no admin rights,
  walks the user through one admin script in their own terminal, and re-checks. Asks before every action,
  labels each one as vetted or improvised, backs up everything it changes, and keeps an undo log. Use when
  someone asks whether their machine is affected by the eMudhra certificate compromise, asks to remove trust
  in the compromised eMudhra certificates, mentions the emSign or AAA Certificate Services intermediates or
  emudhra.we-have-a-problem.com, or invokes /remediate-emudhra-on-my-machine.
license: MIT
compatibility: >-
  Needs an agent with a shell tool on the computer being fixed. macOS and Linux need bash and curl; Windows
  needs Windows PowerShell 5.1 or later. Network access is required for the live checks.
metadata:
  version: "1.1.1"
  tags: "security, incident-response, tls, certificates, trust-store, endpoint"
  repository: "https://github.com/adamzr/remediate-emudhra-on-my-machine"
---

# Remediate the October 2026 eMudhra certificate compromise

**Preflight (needs a system shell).** On macOS or Linux run `for t in bash curl; do command -v "$t" >/dev/null || echo "MISSING: $t"; done`. On Windows run `command -v powershell.exe || echo "MISSING: powershell.exe"` from a bash-style shell (such as Git Bash, which Claude Code uses), or `Get-Command powershell.exe` from PowerShell. If this agent has no shell tool at all (for example a chat-only app), stop and tell the user to run this skill in an agent with a terminal on the computer being fixed, such as Claude Code. If a tool prints `MISSING`, stop and name it. Do not work around either case.

## Background (tell the user in two sentences)

Eight eMudhra intermediate certificate keys were compromised, so an attacker who can intercept network traffic could impersonate websites to software that still trusts them. Browsers and operating systems received automatic blocks, but command-line tools, programming languages, and Java keep their own certificate lists and need fixing by hand, and some built-in tools need an admin step. Source: <https://emudhra.we-have-a-problem.com/>.

## Ground rules (apply to every step)

These override any instinct to move faster.

1. **Ask before every action.** One action is one command, script run, or file edit. Read-only commands that only list or test also need a yes, except the initial check in step 2, which the user approves once. Never chain several changes behind one approval unless the user agreed to that exact list.
2. **Label every action** with one of these three tags, in bold, at the start of the request:
   - **Vetted script**: a script in this skill's `scripts/` directory, shipped and reviewed as part of this skill.
   - **Vetted recipe**: an exact command from `references/fix-recipes.md`, with only a path or version substituted.
   - **Improvised**: anything else written for this machine, including fixes for errors. Say plainly that it has not been reviewed as part of this skill.
3. **Explain each action** using this template, in plain language:

   > **Vetted script** · Upgrade pip and certifi in your Python 3.12 environment
   > **What it does:** installs the fixed versions of two Python packages inside `~/.pyenv/versions/3.12.12`.
   > **Why it's safe:** it only touches that one environment, records the old versions, and can be undone with one logged command. It doesn't need your password.
   > **Command:** `bash ".../scripts/fix-python-env.sh" ~/.pyenv/versions/3.12.12/bin/python3`
   > OK to run it?

4. **Back up and log.** Vetted scripts back up and log themselves. Before an improvised or recipe action changes a file, copy it into the `backups` folder of the state folder: `~/.remediate-emudhra/` (Windows: `%USERPROFILE%\.remediate-emudhra\`), or `REMEDIATE_EMUDHRA_STATE_DIR` when set. After it, append to `actions.log` in that folder with `rem_log` (from `scripts/lib.sh`) or `Write-RemLog` (from `scripts/lib.ps1`), always including an exact undo command. The log format is: time, source, action, detail, undo. Writing the backup and the log entry is part of the action the user approved; don't ask separately for it. To reverse changes, replay the undo commands newest first.
5. **Never run sudo or an elevated PowerShell from the agent.** Admin steps are done by the user in their own terminal, guided by `references/terminal-walkthrough.md`.
6. **Never weaken security to get past an error.** That includes disabling TLS verification, `--break-system-packages`, removing Windows root certificates, and killing processes by name. The full list is at the end of `references/fix-recipes.md`.
7. **Don't uninstall anything or change anything outside this incident** unless the user asks for that specific thing separately.
8. **When unsure, stop and ask.** If the user seems unsure, slow down, explain more, and offer to skip that item and record it as open.

**Find this skill's folder once, at the start.** `SKILL_DIR` is the directory that contains this `SKILL.md`. Claude Code states it when the skill loads ("Base directory for this skill"); other agents know the path they read this file from. Never search the disk for it; if it is unknown, ask the user. Most agents do not keep shell variables between commands, so write that absolute path into every command where this skill shows `$SKILL_DIR`, rather than setting a variable once. Forward slashes work in paths on every OS, including in PowerShell.

**Project folders.** The check looks for project virtualenvs and lock files in whichever of `~/Development`, `~/dev`, `~/src`, `~/code`, `~/projects`, `~/repos`, `~/git`, and `~/workspace` exist (on Windows, under the user folder, plus `source\repos`). If it reports `INFO|projects|none`, or the user keeps code elsewhere, ask where, and run the check with `REMEDIATE_EMUDHRA_PROJECTS` set to those folders (separated by `:` on macOS and Linux, `;` on Windows).

## Workflow

### 1. Introduce the plan

Briefly explain the background and these ground rules. Say how long it usually takes (10 to 30 minutes, longer if an OS update is needed) and that every change can be undone from the log. Ask whether they are ready.

### 2. Run the read-only check (vetted script)

Ask once, then run:

- macOS/Linux: `bash "$SKILL_DIR/scripts/check.sh"`
- Windows: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$SKILL_DIR/scripts/check.ps1"`

It changes nothing on the system and saves its report under the state folder. Each line is `STATUS|AREA|ITEM|DETAIL`. Summarize the results for the user in a short table grouped as **needs fixing** (FAIL), **worth knowing** (WARN), and **fine** (PASS). Keep INFO lines for the end.

### 2a. Windows with WSL

If the Windows check lists `WARN|wsl|<distro>` lines, each distribution is a separate Linux system with its own trust store, Python, Node, and git, and needs its own pass through this workflow. For each one, ask, then run the Linux check inside it (**Vetted script**). From a bash-style shell such as Git Bash:

```bash
LINUX_DIR="$(MSYS_NO_PATHCONV=1 wsl.exe -d "<distro>" -e wslpath -a '<Windows path of SKILL_DIR>' | tr -d '\r')"
MSYS_NO_PATHCONV=1 wsl.exe -d "<distro>" -e bash "$LINUX_DIR/scripts/check.sh"
```

In Git Bash, always prefix `wsl.exe` with `MSYS_NO_PATHCONV=1`; otherwise it rewrites every `/path` argument into a Windows path and the command fails. From PowerShell, drop the prefix. Treat the results like a Linux machine's for steps 3 to 5: user-level fixes run inside the distribution with `wsl.exe -d "<distro>" -e <program> <args>` (`-e` runs the program directly, without the distribution's shell re-parsing the arguments), and its admin step follows the WSL section of `references/terminal-walkthrough.md`. Distributions named `docker-desktop*` belong to Docker and are skipped. If the agent itself is running inside WSL (`WARN|os|WSL`), do the reverse: also run `check.ps1` on the Windows side with `powershell.exe`.

### 3. Fix what needs no admin rights

Work through the FAIL lines in this order, one action at a time, each using the request template. `references/fix-recipes.md` has the command and undo for each. Read the matching section before proposing anything.

1. Python interpreters, with `scripts/fix-python-env.sh` or `.ps1` (vetted script), then project virtualenvs as one listed batch. If uv FAILs, upgrade it (item 4) first, because the fix script uses `uv pip` for uv-created virtualenvs.
2. Node.js: install the fixed release on the same line and make it the default.
3. Git on Windows: switch to the Windows certificate store.
4. Go, uv, rustup, Deno, Bun, conda, mise, pixi, Claude Code, and Homebrew's `ca-certificates` and `certifi`. A Java FAIL is fixed best by upgrading that JDK (see Java in `references/fix-recipes.md`); the admin step covers JDKs the user can't upgrade yet.
5. Lock files that pin an old certifi (`WARN|lockfile`): one repository at a time, only for repositories the user works on, and only once uv PASSes.

Every `brew upgrade` follows the Homebrew rules in `references/fix-recipes.md`: dry run first, then the two variables that keep old kegs and stop Homebrew from upgrading unrelated dependents.

If a command fails, show the error and explain it in plain words. Propose a fix labeled **Improvised**. If a vetted script itself misbehaved, note it for step 7.

### 4. Guide the admin step

Skip this step only when no FAIL line is in the `truststore`, `curl`, `git`, `windows`, `java`, or `os` areas, and there is no `network` FAIL.

On macOS, if the check shows `WARN|os|macOS`, or the user says an update is waiting in Software Update, offer to install it first: a macOS update rewrites `/etc/ssl/cert.pem` and undoes the admin script's first step. If the user would rather update later, go ahead, and tell them to run the admin script again after the update.

Tell the user this is the one step they run themselves, because it needs their computer password, which the agent must never handle. Offer the dry-run first. Then follow `references/terminal-walkthrough.md` for their OS one step at a time, waiting for confirmation after each. The scripts:

| OS | Vetted script |
|---|---|
| macOS | `scripts/admin-fix-macos.sh` |
| Windows | `scripts/admin-fix-windows.ps1` |
| Debian, Ubuntu, Pop!_OS, Mint | `scripts/admin-fix-linux.sh` |
| Fedora, RHEL, CentOS Stream, Rocky, Alma, Amazon Linux | `scripts/admin-fix-linux.sh` |
| Arch and Arch-based | `scripts/admin-fix-linux.sh` |
| NixOS | `scripts/admin-fix-linux.sh` prints a `configuration.nix` change for the user to apply |

On any other Linux distribution the script stops without changing anything; record the trust store as open and point the user to the manual steps on the incident site.

Before they run it, read the script's header comment aloud in plain words: what it changes and how it backs up and logs.

### 5. Re-check

When the user says done, run the check again (same approval rule as step 2) and compare it with the first run. A `FAIL|network` line means the run could not verify anything: never call the machine fixed until a check with network access passes. An `INFO|node|PATH` line after a Node default switch is expected: the agent keeps the PATH it started with, and the check tests the default that new terminals get. For anything still failing, explain why and either fix it (back to step 3 or 4) or record it as open with the reason.

### 6. Things only the user can do

List what remains outside the agent, from the last section of `references/fix-recipes.md`: OS updates (macOS 15.8+, 26.7+, or 27; Windows Update; the Linux package manager), browser updates and the four test URLs, app updates, and phones (iOS 26.7+ or 27; restart Android). Ask them to open the four test URLs from the check's `INFO|browsers` line in each browser now (two of them use chains never logged to Certificate Transparency, which some browser blocks rely on) and tell you whether all four show a certificate error.

### 7. Summarize, and report problems with the skill

Show the user a short summary. Every field holds a real answer; if the browser test from step 6 is not settled, ask before writing it, and never leave a `<...>` placeholder or "fill in later" in it:

```text
eMudhra remediation: <macOS 26.7.1 | Windows 11 | Ubuntu 24.04 | ...>
Result: <All checks pass | N items still open>
Fixed today: <short list, e.g. system trust store, 3 Python environments, Node 24.22.1, 2 JDKs>
Still open: <short list with reason, e.g. "macOS update to 26.7 (needs restart tonight)", or "none">
Browsers tested against the test sites: <yes / no>
```

If a vetted script or recipe failed, gave a wrong result, or missed a tool, offer to draft a bug report for <https://github.com/adamzr/remediate-emudhra-on-my-machine/issues>. Include the OS, the agent, the relevant check lines or error text, and what happened. Scrub it first: no usernames, hostnames, home-directory paths, IP addresses, tokens, or the action log. Show the draft and give the user the new-issue link to post it themselves. Run `gh issue create` only if the user asks for that and `gh auth status` succeeds. Suspected security problems in the skill go to the repository's private security advisory form instead, never to a public issue.

End by telling the user where the action log and backups are, and that `actions.log` lists the undo command for every change.

## Gotchas

- **macOS curl and git need the keychain step too.** Apple's tools check `/etc/ssl/cert.pem` first and fall back to the keychain roots without checking revocation. The site's `cert.pem` fix alone leaves the emSign chain trusted. The admin script's "Never Trust" step closes that gap.
- **Windows Python's urllib** ignores the Untrusted store where Microsoft's block lives. It is a WARN, not a FAIL. pip and requests are covered by the pip and certifi upgrades. Don't try to fix it by removing Windows root certificates.
- **`check.sh` reports every interpreter it finds**, including tools' private ones. Fix the ones the user actually uses first, and treat EOL Pythons and unused Node versions as cleanup to suggest, not mandatory fixes.
- **conda environments mix two installers.** The check finds named environments too (`envs/*` and `~/.conda/environments.txt`). In each one, a package may have come from conda or from pip; `fix-python-env.sh` upgrades each with the tool that installed it, so never run `conda update` on a package pip installed, or the reverse.
- **uv virtualenvs have no pip.** `fix-python-env.sh` upgrades their certifi with `uv pip`; don't improvise a pip bootstrap.
- **System Pythons** (`/usr/bin/python3` on macOS and Linux) use the system trust store; the check reports their pip as PASS once the admin step is done. Never modify them. Apple's python3 ships no certifi, so a certifi the check finds there was added with pip and is a FAIL; the OS-owned Python recipes say which ones the user can fix.
- **`brew upgrade` without the recipe's variables upgrades every dependent.** For `ca-certificates` that can pull in Node, Deno, a new Python, and ffmpeg. Always dry-run and use both variables.
- **Homebrew's Pythons import the separate `certifi` formula when another formula installed it.** Upgrading `python@3.X` fixes pip and leaves that certifi old.
- **A macOS update restores the two roots in `/etc/ssl/cert.pem`.** Re-run the check after any macOS update, and the admin script if it FAILs.
- **On Arch, the package update is a full system upgrade.** Arch does not support partial upgrades, so the admin script runs `pacman -Syu`. Say so before the user runs it, and offer the dry run.
- **Windows virtualenvs use `Lib\site-packages` and `Scripts\python.exe`**, not `lib/python3.X/site-packages` and `bin/python`. The virtualenv recipe matches both.
- **An Xcode or Command Line Tools update** can remove the `PIP_CERT` line the macOS admin script adds. Re-running the admin script restores it.
- **Patched JDKs keep the roots in `cacerts`.** Their fix is in `blocked.certs`, so the check tests JDKs live instead of looking for the roots, and the admin script leaves patched JDKs alone. For a JDK that FAILs, upgrading it to the fixed release on its line is better than the admin script's root removal; installing an older, unpatched JDK brings the roots back.
- **A python.org Python that "cannot verify any site"** is broken but not exposed. Optional to fix.
- **Pasting into terminals:** Command+V on macOS, Ctrl+Shift+V in Linux terminals, and right-click in Windows PowerShell.

## Additional resources

- **`references/fix-recipes.md`**: fixed versions table, per-tool commands with undo, and things never to do. Read before proposing any fix.
- **`references/terminal-walkthrough.md`**: plain-language steps for opening a terminal and running the admin script on each OS. Read before step 4.
- **`assets/impacted-intermediates.json`**: the 16 compromised intermediates from the incident site (SHA-256 pinned in `scripts/lib.ps1`). `assets/compromised-intermediates/` holds the same certificates as PEM files for macOS.
