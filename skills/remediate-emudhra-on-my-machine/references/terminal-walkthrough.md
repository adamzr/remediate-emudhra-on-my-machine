# Walking a non-technical user through the admin script

## Contents

- [Before starting](#before-starting)
- [macOS](#macos)
- [Windows](#windows)
- [Linux (Ubuntu, Debian, Fedora, Arch, and similar)](#linux-ubuntu-debian-fedora-arch-and-similar)
- [WSL on Windows](#wsl-on-windows)
- [NixOS](#nixos)
- [When something goes wrong](#when-something-goes-wrong)

## Before starting

Give one step at a time and wait for the user to confirm each before moving on. Use plain words: "window", "paste", "press Return". Avoid jargon such as sudo, shell, elevated, or PATH unless the user uses it first.

Prepare the command first, with the real absolute path of the skill's script substituted in, so the user pastes one line and types nothing else. Use the real path of `SKILL_DIR`, not the variable. Show the command in a code block on its own.

Explain, in one or two sentences, what the script will change and that it saves a backup of everything and writes an undo log. Offer the `--dry-run` (macOS/Linux) or `-DryRun` (Windows) version first for anyone who wants to see the plan without changing anything.

## macOS

1. "Press Command and Space together, type **Terminal**, and press Return. A window with text opens." (If they use iTerm2, that works too.)
2. "Click inside that window, then paste the command I give you: press Command and V."
3. "Press Return."
4. "It asks for **Password**. Type the password you use to log in to this Mac and press Return. Nothing appears as you type, not even dots. That is normal." If Touch ID is set up for the terminal, they may be asked to touch the sensor instead.
5. "A box may pop up asking to change trust settings. That is this script. Approve it with your password or Touch ID." The first run can show it once per certificate, up to 16 times; later runs skip certificates already blocked. If they click Cancel, that certificate is skipped and running the script again retries it.
6. "When you see **Done. Go back to your AI agent**, come back here and type **done**."

Paste the command:

```bash
bash "<absolute path>/scripts/admin-fix-macos.sh"
```

## Windows

1. "Click the Start button (or press the Windows key) and type **PowerShell**."
2. "In the results, **right-click Windows PowerShell** and choose **Run as administrator**."
3. "Windows asks **Do you want to allow this app to make changes to your device?** Click **Yes**." If it asks for an administrator password instead, the user has a standard account. Stop here, because whoever administers this computer (often IT) needs to run this step.
4. "The window title should start with **Administrator**. Click inside it, then right-click once to paste the command I give you." (Ctrl+V also works in newer versions.)
5. "Press Enter."
6. "When you see **Done. Go back to your AI agent**, come back here and type **done**."

Paste the command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<absolute path>/scripts/admin-fix-windows.ps1"
```

`-ExecutionPolicy Bypass` applies to this one command only; it does not change the computer's settings. Say that if the user asks.

## Linux (Ubuntu, Debian, Fedora, Arch, and similar)

1. "Press the Super key (the one with the Windows or distribution logo), type **Terminal**, and press Enter."
2. "Paste the command: press Ctrl+Shift+V." (Ctrl+V does not paste in most Linux terminals.)
3. "Press Enter. When it asks for your password, type your login password and press Enter. Nothing appears as you type. That is normal."
4. "It may show a lot of text while it updates packages. Wait for **Done. Go back to your AI agent**, then come back and type **done**."

```bash
bash "<absolute path>/scripts/admin-fix-linux.sh"
```

On **Arch**, step 1 of the script is a full system upgrade (`pacman -Syu`), because Arch does not support updating one package alone. Say that before they run it. pacman lists every package it will upgrade and asks **Proceed with installation? [Y/n]**; tell them it is their choice, and that answering **n** skips the upgrade while the script still applies the certificate block in its step 2.

## WSL on Windows

Each WSL distribution (usually Ubuntu) has its own admin password, separate from the Windows one: the Linux password chosen when the distribution was first set up.

1. "Click the Start button and type the name of the distribution, for example **Ubuntu**, and open it. A black window opens."
2. "Paste the command I give you: right-click inside the window." (Ctrl+Shift+V also works in Windows Terminal.)
3. "Press Enter. When it asks for your password, type your **Linux** password (the one for this Ubuntu, not your Windows password) and press Enter. Nothing appears as you type."
4. "Wait for **Done. Go back to your AI agent**, then come back and type **done**."

Use the Linux script with the path as seen from inside the distribution (`/mnt/c/...`; get it with `wslpath -a`):

```bash
bash "/mnt/c/<path>/scripts/admin-fix-linux.sh"
```

If they don't remember the Linux password, stop: resetting it needs `wsl -u root` and `passwd`, which is improvised. Offer to record the distribution as open instead.

## NixOS

The script only prints instructions on NixOS. A NixOS user is technical; show the `security.pki.caCertificateBlacklist` setting and `sudo nixos-rebuild switch`, and let them apply it to their own configuration (which may be a flake or a separate repository).

## When something goes wrong

- **"command not found" or "No such file":** the path was mistyped or cut off. Give the command again and ask them to paste, not type.
- **"is not in the sudoers file" (Mac/Linux) or the administrator prompt asks for someone else's password (Windows):** the account has no admin rights. Stop. Tell them whoever administers this computer (often IT) needs to run this step, and skip to the parts that need no admin rights.
- **The window closed or froze:** nothing is half-applied; each step is separate and the script can be run again safely.
- **Anything unexpected:** ask the user to copy the last ten lines from the window and paste them here. Diagnose before suggesting anything else, and label any new command as improvised.
