#!/usr/bin/env python3
"""Validate the skill in skills/ against the Agent Skills spec and the authoring rules in CONTRIBUTING.md.

Usage:
    python3 tools/validate_skill.py                 # everything except the version-bump rule
    python3 tools/validate_skill.py --since main    # also: a change under skills/ must bump the version

Checks, for every skills/<name>/SKILL.md:
  - frontmatter is valid YAML with only the Agent Skills fields; `name` follows the naming rules and
    matches its directory; `description` is at most 1,024 characters and has no XML tags; `metadata`
    values are strings
  - the SKILL.md body is under 500 lines
  - reference files over 100 lines start with a `## Contents` section, and never link on to a third file
  - every `scripts/...`, `references/...`, and `assets/...` path SKILL.md names exists
And, for every Markdown file in the repository: no em-dashes or en-dashes, and no personal home paths.
And versioning: the newest CHANGELOG.md entry is the skill's `metadata.version`, and with --since REF,
any change under skills/ since REF raises that version (semver).

Pure stdlib plus PyYAML. `npx skills-ref validate` runs in CI as a cross-check against spec drift.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

# Agent Skills frontmatter is a closed field set (https://agentskills.io/specification).
SKILL_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
SKILL_NAME = re.compile(r"^(?!.*--)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
# claude.ai rejects a skill whose description contains anything that parses as an XML tag.
XML_TAG = re.compile(r"<[A-Za-z/!?][^<>]*>")
# A markdown link whose target is a local .md file: `](RECOVERY.md)`, `](refs/x.md#anchor)`.
REF_LINK = re.compile(r"\]\(((?!https?://)[^)#\s]+\.md)(?:#[^)]*)?\)")
SKILL_PATH = re.compile(r"`((?:scripts|references|assets)/[A-Za-z0-9_./-]+)`")
DASHES = re.compile("[–—]")
HOME_PATH = re.compile(r"/(?:Users|home)/(?!<|\{)[A-Za-z0-9._-]+/")

MAX_DESCRIPTION = 1024
MAX_COMPATIBILITY = 500
MAX_SKILL_BODY_LINES = 500
TOC_REQUIRED_OVER = 100

failures: list[str] = []


def fail(where: Path, msg: str) -> None:
    failures.append(f"{where.relative_to(ROOT)}: {msg}")


def load_frontmatter(skill_md: Path) -> dict | None:
    match = re.match(r"^---\n(.*?)\n---\n", skill_md.read_text(), re.S)
    if not match:
        fail(skill_md, "no YAML frontmatter delimited by `---`")
        return None
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        at = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
        fail(skill_md, f"frontmatter is not valid YAML{at}. Quote values containing \": \" or use `>-`.")
        return None
    if not isinstance(data, dict):
        fail(skill_md, "frontmatter is not a mapping")
        return None
    return data


def check_skill(skill_dir: Path) -> None:
    skill_md = skill_dir / "SKILL.md"
    data = load_frontmatter(skill_md)
    if data is None:
        return

    extra = sorted(set(data) - SKILL_FIELDS)
    if extra:
        fail(skill_md, f"frontmatter fields outside the Agent Skills spec: {extra}. Put them under `metadata:`.")

    name = data.get("name")
    if not name:
        fail(skill_md, "`name` is required")
    elif not SKILL_NAME.match(str(name)) or len(str(name)) > 64:
        fail(skill_md, f"`name` {name!r} breaks the Agent Skills naming rules")
    elif name != skill_dir.name:
        fail(skill_md, f"`name` {name!r} must match directory {skill_dir.name!r}")

    description = data.get("description")
    if not description:
        fail(skill_md, "`description` is required")
    else:
        if len(description) > MAX_DESCRIPTION:
            fail(skill_md, f"`description` is {len(description)} characters, over the {MAX_DESCRIPTION} limit")
        tags = XML_TAG.findall(description)
        if tags:
            fail(skill_md, f"`description` contains XML tags {tags}. Use {{braces}} for placeholders.")

    compatibility = data.get("compatibility")
    if compatibility and len(str(compatibility)) > MAX_COMPATIBILITY:
        fail(skill_md, f"`compatibility` is over the {MAX_COMPATIBILITY}-character limit")

    metadata = data.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            fail(skill_md, "`metadata` must be a mapping")
        else:
            bad = sorted(k for k, v in metadata.items() if not isinstance(v, str))
            if bad:
                fail(skill_md, f"`metadata` values must be strings, these are not: {bad}")

    text = skill_md.read_text()
    body = re.split(r"^---$", text, maxsplit=2, flags=re.M)[-1]
    if len(body.splitlines()) >= MAX_SKILL_BODY_LINES:
        fail(skill_md, f"body is {len(body.splitlines())} lines; keep it under {MAX_SKILL_BODY_LINES} "
                       "and move detail into a reference file")

    for rel in sorted(set(SKILL_PATH.findall(text))):
        if not (skill_dir / rel.rstrip("/.")).exists():
            fail(skill_md, f"names `{rel}`, which does not exist")

    for ref in sorted(skill_dir.rglob("*.md")):
        if ref.name == "SKILL.md":
            continue
        ref_text = ref.read_text()
        lines = ref_text.splitlines()
        if len(lines) > TOC_REQUIRED_OVER and not any(l.strip() == "## Contents" for l in lines[:40]):
            fail(ref, f"reference file is {len(lines)} lines and needs a `## Contents` table of contents")
        # Reference files are one level deep: they may point back to SKILL.md, never on to a third file.
        for target in REF_LINK.findall(re.sub(r"```.*?```", "", ref_text, flags=re.S)):
            if Path(target).name != "SKILL.md":
                fail(ref, f"links to `{target}`; a reference file must not send the reader to a third file")


def check_markdown() -> None:
    for md in sorted(ROOT.rglob("*.md")):
        if any(part in {".git", "node_modules"} for part in md.parts):
            continue
        for n, line in enumerate(md.read_text().splitlines(), 1):
            if DASHES.search(line):
                fail(md, f"line {n} has an em-dash or en-dash; rewrite the sentence instead")
            if HOME_PATH.search(line):
                fail(md, f"line {n} has a personal home-directory path")


def skill_version(text: str) -> str | None:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    data = yaml.safe_load(match.group(1)) if match else None
    meta = (data or {}).get("metadata") or {}
    return meta.get("version") if isinstance(meta, dict) else None


def semver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def check_versions(skills: list[Path], since: str | None) -> None:
    changelog = ROOT / "CHANGELOG.md"
    top = re.search(r"^## (\d+\.\d+\.\d+)", changelog.read_text(), re.M) if changelog.is_file() else None
    for skill_dir in skills:
        skill_md = skill_dir / "SKILL.md"
        now = skill_version(skill_md.read_text())
        if not now:
            fail(skill_md, "`metadata.version` is required")
            continue
        if not top or top.group(1) != now:
            fail(changelog, f"the newest entry must be `## {now}` (the skill's metadata.version)")
        if since is None:
            continue
        rel = skill_dir.relative_to(ROOT).as_posix()
        changed = subprocess.run(["git", "diff", "--name-only", f"{since}...HEAD", "--", rel],
                                 cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        if not changed:
            continue
        old = subprocess.run(["git", "show", f"{since}:{rel}/SKILL.md"], cwd=ROOT, capture_output=True, text=True)
        before = skill_version(old.stdout) if old.returncode == 0 else None
        if before and semver(now) <= semver(before):
            fail(skill_md, f"files under {rel}/ changed since {since}, so `metadata.version` must rise above {before}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", help="git ref to compare against for the version-bump rule, e.g. origin/main")
    args = parser.parse_args()
    skills = sorted(p.parent for p in (ROOT / "skills").glob("*/SKILL.md"))
    if not skills:
        failures.append("skills/: no skills/<name>/SKILL.md found")
    for skill_dir in skills:
        check_skill(skill_dir)
    check_markdown()
    check_versions(skills, args.since)
    if failures:
        print("\n".join(f"FAIL {f}" for f in failures))
        return 1
    print(f"OK: {len(skills)} skill(s) valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
