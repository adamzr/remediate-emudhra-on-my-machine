# Contributing

Thanks for helping. Bug reports from real machines are the most valuable contribution: each OS, package manager, and toolchain behaves a little differently, and the check gets better with every case it learns.

## Reporting a bug

Open an [issue](https://github.com/adamzr/remediate-emudhra-on-my-machine/issues/new/choose) using the bug report form. Include your OS and version, which agent you used, the relevant check lines (`STATUS|AREA|ITEM|DETAIL`), and what happened. Remove usernames, hostnames, home-directory paths, and IP addresses first, and never attach `actions.log`.

Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Layout

```
skills/remediate-emudhra-on-my-machine/
  SKILL.md        the workflow the agent follows
  references/     fix recipes and the admin-step walkthrough, loaded when needed
  scripts/        the check, the user-level Python fix, and one admin script per OS
  assets/         the 16 compromised intermediates, as JSON and PEM
tools/validate_skill.py   repository checks, run in CI
```

## Rules for scripts

- **Portability.** Bash scripts must run on stock macOS bash 3.2 and on GNU/Linux, with BSD and GNU userland alike (no `sed -i` without a suffix, no `grep -P`, no `readlink -f` without a fallback). PowerShell scripts must run on Windows PowerShell 5.1.
- **The check is read-only.** `check.sh` and `check.ps1` change nothing except their report in the state folder. They never report PASS when a result could not be determined; use WARN, or `FAIL|network` when offline.
- **Admin scripts are run by the user, never by the agent.** They ask for `sudo` only where needed, refuse to run as root, and support `--dry-run`.
- **Every change is backed up and logged with an exact undo command**, using `rem_backup`, `rem_restore_cmd`, and `rem_log` (`Backup-RemFile` and `Write-RemLog` on Windows).
- **Never weaken security**, even temporarily: no disabling TLS verification, no `--break-system-packages`, no removing Windows root certificates, no killing processes by name.
- **Follow the incident site.** Where https://emudhra.we-have-a-problem.com/ prescribes a fix, apply it exactly, and explain any deviation in the script's header comment.

## Rules for the skill text

The skill follows the [Agent Skills specification](https://agentskills.io/specification) and Anthropic's [skill authoring best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices).
- `SKILL.md` stays under 500 lines. Put detail in `references/`, and say in `SKILL.md` when to read each file.
- Reference files are one level deep, and files over 100 lines start with `## Contents`.
- The `description` is at most 1,024 characters, in the third person, and says both what the skill does and when to use it. Don't put anything that looks like an XML tag in it.
- No em-dashes or en-dashes in any Markdown file. Rewrite the sentence instead.

## Checks to run before a pull request

```bash
shellcheck -x -S warning skills/*/scripts/*.sh
python3 tools/validate_skill.py           # needs PyYAML
npx --yes skills-ref@0.1.5 validate skills/remediate-emudhra-on-my-machine
bash skills/remediate-emudhra-on-my-machine/scripts/check.sh   # read-only
```

CI runs these as well, plus the check on macOS, Ubuntu, and Windows. It also runs the Linux admin script end to end in Debian, Ubuntu, Fedora, Rocky, and Arch containers, and does a test install with `npx skills add`.

Say in the pull request how you tested on a real machine. In the same pull request, bump `metadata.version` in `SKILL.md` ([semver](https://semver.org): patch for fixes, minor for new checks or platforms) and add a `CHANGELOG.md` entry.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
