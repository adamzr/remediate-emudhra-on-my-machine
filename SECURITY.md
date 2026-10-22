# Security policy

This skill changes how a computer decides which websites to trust, and its admin scripts run with administrator rights. Problems in it can matter, so please report them privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/adamzr/remediate-emudhra-on-my-machine/security/advisories/new)). Do not open a public issue or pull request for a security problem.

Please include:
- what is wrong and its effect;
- the affected script or file and version;
- how to reproduce it, on which operating system;
- whether you know of anyone exploiting it.

You should get an acknowledgment within 3 business days. Fixes are released as a new version, and reporters are credited in the advisory unless they ask not to be.

## What counts

Examples of what to report:
- a check that reports PASS while the machine still trusts a compromised chain;
- an admin script that changes something its header comment does not describe, or that can be tricked into doing so (for example, through a crafted file path or environment variable);
- a backup or undo command that would leave a system file with the wrong owner or permissions;
- instructions in the skill that could lead an agent to weaken TLS verification or run commands with more privilege than needed.

Problems with the incident itself, or with a vendor's fix, belong with that vendor.

## Supported versions

Only the latest release is supported. Install or update with `npx skills add adamzr/remediate-emudhra-on-my-machine -g`.

## Verifying what you run

The skill asks before every action, but you can also check the scripts yourself:
- Each admin script (`scripts/admin-fix-*.sh`, `scripts/admin-fix-windows.ps1`) lists everything it changes in its header comment, and supports `--dry-run` (`-DryRun` on Windows).
- The compromised certificates are pinned by SHA-256 fingerprint in `scripts/lib.sh` and `scripts/lib.ps1`, and the Windows script refuses to run if `assets/impacted-intermediates.json` contains anything else. Compare them with the incident site's [impacted-intermediates.json](https://emudhra.we-have-a-problem.com/).
- Every change is backed up and logged with an undo command in `~/.remediate-emudhra/actions.log`.
