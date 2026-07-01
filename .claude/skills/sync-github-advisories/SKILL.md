---
name: sync-github-advisories
description: Sync/migrate MidnightBSD GitHub Security Advisories into OSV YAML files in vulns/midnightbsd/. Use when the local advisory list is behind the GitHub advisories at github.com/MidnightBSD/src/security/advisories, or when asked to import/catch up/backfill MNBSD-YYYY-* advisories.
---

# Sync GitHub Security Advisories → OSV YAML

This skill imports published GitHub Security Advisories (GHSA) from the
MidnightBSD source repo and writes matching OSV-format YAML advisories into
`vulns/midnightbsd/`, keeping the local list in sync with GitHub. The website is
published from these YAML files, so they must stay in sync.

## Data source

GitHub advisories live at
`https://github.com/MidnightBSD/src/security/advisories` and are read via the
REST API with the `gh` CLI:

```bash
gh api /repos/MidnightBSD/src/security-advisories --paginate
```

Each advisory's `summary` starts with its MNBSD identifier, e.g.
`"MNBSD-2026-63 Multiple vulnerabilities in OpenZFS ..."`. That prefix is how a
GHSA is mapped to an `MNBSD-YYYY-ID.yaml` file.

## Quick start

Run the bundled script from the repository root. It fetches all published
advisories, writes YAML for any MNBSD id not already present, and bumps
`latest-id.txt`:

```bash
python3 .claude/skills/sync-github-advisories/sync_advisories.py
```

Common variations:

```bash
# Preview without writing
python3 .claude/skills/sync-github-advisories/sync_advisories.py --dry-run

# Only a specific range / year
python3 .claude/skills/sync-github-advisories/sync_advisories.py --year 2026 --from 17 --to 63

# Regenerate (overwrite) files that already exist
python3 .claude/skills/sync-github-advisories/sync_advisories.py --from 40 --to 45 --force
```

By default existing YAML files are **skipped** (never clobbered). Use `--force`
only when you intend to regenerate them.

After writing YAML, regenerate the HTML:

```bash
python3 scripts/osvtohtml.py vulns/midnightbsd
```

## Field mapping (GHSA → OSV YAML)

The script encodes the following procedure. Understand it so you can hand-fix
edge cases the script gets wrong.

| OSV YAML field        | Source in the GitHub advisory                                                                 |
|-----------------------|-----------------------------------------------------------------------------------------------|
| `id`                  | `MNBSD-YYYY-ID` parsed from the `summary` prefix                                               |
| `summary`             | `summary` with the `MNBSD-YYYY-ID ` prefix stripped (JSON-quoted if it starts with `"` or has `: `) |
| `details`             | The advisory `description`, minus the Patches/References/Solution/Credits/Affected-Versions sections, with markdown headers, `**bold**`, and `` `backticks` `` stripped (it renders inside a single `<p>`) |
| `affected[].package.name` | `vulnerabilities[].package.name` (kept verbatim, e.g. `kernel/posixshm`, `libc/iconv`, `openzfs`) |
| `affected[].package.ecosystem` | Always `MidnightBSD`                                                                  |
| `affected[].ranges` (ECOSYSTEM) | `introduced` from `vulnerable_version_range` (`0`, unless it uses `>= X`); `fixed` = first version in `patched_versions` |
| `references`          | URLs in the description's References section; else `cve.org` records for each CVE; else the GHSA `html_url` |
| `aliases`             | **All** `CVE-…` ids found in the summary + description (not just `cve_id` — multi-CVE advisories list several) |
| `modified` / `published` | `published_at` (falls back to `updated_at`/`created_at`)                                    |

`latest-id.txt` is updated to the highest ID of the most recent year processed.

## Things to watch for

- **No CVE yet.** Some advisories (e.g. msearch) have no CVE assigned. The
  script writes no `aliases` and references the GHSA advisory URL instead. This
  is expected — don't invent a CVE.
- **Multi-CVE advisories.** The GitHub `cve_id`/`identifiers` fields often list
  only the primary CVE; the script scrapes every `CVE-...` from the text so all
  are captured as aliases.
- **Package names.** Newer advisories use qualified names like `kernel/posixshm`
  or `libc/iconv`. These are kept as-is. Collapse to `kernel` only if the
  maintainer asks.
- **Verify before committing.** Confirm YAML parses and spot-check a simple and a
  multi-vuln file:
  ```bash
  python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('vulns/midnightbsd/*.yaml')]"
  ```
- Nothing is committed automatically — review the diff, then commit the new
  `.yaml`/`.html` files and `latest-id.txt`.