# remediate-emudhra-on-my-machine

An [Agent Skill](https://agentskills.io) that checks whether your computer still trusts the compromised eMudhra certificate chains from the October 2026 incident, and removes that trust everywhere it can.

## Why

In October 2026, eight eMudhra intermediate certificate authorities were found to have private keys that the CA generated incorrectly, so anyone can recover them from the certificates. Anyone who controls a network you use (a hostile Wi-Fi hotspot, for example) could use them to impersonate any website to software that still trusts those chains. See the incident write-up at [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/).

Browsers and operating systems received automatic blocks. Much of the software on a developer's machine did not, because it keeps its own list of trusted certificates. That includes curl, git, Python and pip, Node.js, and Java. This skill finds all of those and fixes them.

## What it checks

| Area | What is checked |
|---|---|
| System trust store | macOS `/etc/ssl/cert.pem` and keychain, the Windows certificate stores, and the Linux CA bundle, plus live tests against the incident's test hosts |
| curl and git | Every copy found, tested live |
| Python | Every interpreter (pyenv, python.org, Homebrew, uv, system, and every conda, mamba, or micromamba environment), its pip and certifi, and project virtualenvs |
| Node.js | Every installed version (nvm, fnm, Volta, Homebrew), plus a live test of the default |
| Java | Every JDK found, tested live where possible (patched JDKs block the intermediates in `blocked.certs`) |
| Other tools | Go, uv, rustup, Deno, Bun, conda, mise, pixi, Claude Code itself, and Homebrew's `ca-certificates` and `certifi` |
| WSL | Each Linux distribution under Windows, checked as its own machine |
| Lock files | Repositories whose `uv.lock` pins a vulnerable certifi |

Supported systems: macOS, Windows 10 and 11 (including WSL), Debian/Ubuntu and derivatives, Fedora/RHEL and derivatives, Arch and derivatives, and NixOS.

## How it keeps you safe

- **It asks before every action** and explains each one in plain language. It labels each action as a reviewed script, a reviewed recipe, or an improvised command written for your machine.
- **It never runs `sudo` or an elevated PowerShell itself.** The one admin step is a script you run in your own terminal. The skill walks you through it and offers a dry run first.
- **Everything it changes is backed up and logged** in `~/.remediate-emudhra/` (`%USERPROFILE%\.remediate-emudhra\` on Windows). `actions.log` has the exact undo command for every change.
- **It never weakens security to get past an error.** For example, it will not disable TLS verification or remove Windows root certificates.

## Install

With the [`skills`](https://github.com/vercel-labs/skills) CLI (requires Node.js):

```bash
npx skills add adamzr/remediate-emudhra-on-my-machine -g
```

`-g` installs it for your user rather than for one project, which suits a fix that applies to the whole machine. To install for one agent only, add `-a`, for example:

```bash
npx skills add adamzr/remediate-emudhra-on-my-machine -g -a claude-code
```

The CLI supports Claude Code, Codex, Cursor, OpenCode, Gemini CLI, GitHub Copilot, and many other agents. Run `npx skills --help` for every option.

## Use

Start your agent on the computer you want to check, then:

- In Claude Code, type `/remediate-emudhra-on-my-machine`.
- In any agent, ask in plain words, for example: "Is my machine affected by the eMudhra certificate compromise?"

A run takes 10 to 30 minutes, and longer if an operating system update is needed. The agent needs a shell tool, so chat-only apps can't run it.

### Without an agent

The read-only check is a plain script that changes nothing on your system. From a clone of this repository (or from the installed copy, for example `~/.claude/skills/remediate-emudhra-on-my-machine/` after a global install for Claude Code, without the leading `skills/`):

```bash
bash skills/remediate-emudhra-on-my-machine/scripts/check.sh
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File skills/remediate-emudhra-on-my-machine/scripts/check.ps1
```

Each output line is `STATUS|AREA|ITEM|DETAIL`, where STATUS is `PASS`, `FAIL`, `WARN`, or `INFO`. The check scans for project virtualenvs and lock files in `~/Development`, `~/dev`, `~/src`, `~/code`, `~/projects`, `~/repos`, `~/git`, and `~/workspace`. To scan other folders, set `REMEDIATE_EMUDHRA_PROJECTS` to a list separated by `:` (`;` on Windows). Reports, backups, and the undo log go to `~/.remediate-emudhra/`, or to `REMEDIATE_EMUDHRA_STATE_DIR` when set.

The fixes are easiest to apply through the skill, since it reads the results and picks the right recipe. The admin scripts in `scripts/` each describe what they change in their header comment, and all of them support `--dry-run` (`-DryRun` on Windows).

## Things it can't fix

Some items need you, or a vendor:

- **Operating system and browser updates.** The skill tells you what to install.
- **Phones.** Update iOS to 26.7 or later. Restart Android.
- **JDKs you can't upgrade yet.** Patched JDKs exist (27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511), and upgrading is the fix. Until then, the admin script removes the affected roots from an unpatched JDK's `cacerts`.
- **Python's urllib on Windows** ignores the store where Microsoft's block lives. No fix exists yet. pip and requests are covered.

## Update

The incident site keeps adding fixed releases, and the skill follows it. Update before each run:

```bash
npx skills update remediate-emudhra-on-my-machine -g
```

## Uninstall

```bash
npx skills remove remediate-emudhra-on-my-machine -g
```

Removing the skill does not undo any fixes, and it leaves `~/.remediate-emudhra/` in place, since that folder holds the backups and the undo log. To reverse a change, replay the undo commands in `actions.log`, newest first; delete the folder once you no longer need them.

## Contributing and security

Bug reports and fixes are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem in the skill itself, follow [SECURITY.md](SECURITY.md) and do not open a public issue.

## License

[MIT](LICENSE). This project is not affiliated with eMudhra, Apple, Microsoft, Google, or any certificate authority. It is provided as is, without warranty: read what each step does before you approve it.
