#!/usr/bin/env python3
"""Sync MidnightBSD GitHub Security Advisories into OSV YAML files.

Fetches published security advisories from a GitHub repository (default
MidnightBSD/src) via the `gh` CLI, maps each one to its MNBSD-YYYY-ID identifier
(parsed from the advisory summary), and writes an OSV-format YAML file for every
advisory that is not already present in vulns/midnightbsd/.

Usage:
  python3 sync_advisories.py [options]

Options:
  --repo OWNER/NAME   GitHub repo to read advisories from (default MidnightBSD/src)
  --out DIR           Output directory (default vulns/midnightbsd relative to CWD)
  --latest-id FILE    latest-id.txt path to update (default ./latest-id.txt)
  --year YYYY         Only process MNBSD-YYYY-* advisories (default: all years)
  --from N            Lowest numeric ID to (re)generate (default: all)
  --to M              Highest numeric ID to (re)generate (default: all)
  --force             Overwrite YAML files that already exist
  --dry-run           Print what would be written without writing

After running, regenerate HTML with:
  python3 scripts/osvtohtml.py vulns/midnightbsd
"""

import argparse, json, os, re, subprocess, sys

EXCLUDE = ('patch', 'reference', 'solution', 'credit', 'affected version')


def fetch_advisories(repo):
    out = subprocess.check_output(
        ['gh', 'api', '/repos/%s/security-advisories' % repo, '--paginate'])
    return json.loads(out)


def split_sections(desc):
    lines = desc.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    sections, head, body = [], None, []
    for ln in lines:
        hm = re.match(r'^\s*#{1,6}\s*(.+?)\s*$', ln)
        if hm:
            if head is not None or body:
                sections.append((head, body))
            head, body = hm.group(1), []
        else:
            body.append(ln)
    if head is not None or body:
        sections.append((head, body))
    return sections


def clean_inline(t):
    t = t.replace('**', '')
    return re.sub(r'`([^`]*)`', r'\1', t)


def build_details(desc):
    parts = []
    for head, body in split_sections(desc):
        if head and any(x in head.lower() for x in EXCLUDE):
            continue
        text = clean_inline('\n'.join(body)).strip()
        if text:
            parts.append(text)
    return re.sub(r'\n{3,}', '\n\n', '\n\n'.join(parts)).strip()


def extract_refs(desc):
    urls = []
    for head, body in split_sections(desc):
        if head and 'reference' in head.lower():
            for ln in body:
                for u in re.findall(r'https?://\S+', ln):
                    urls.append(u.rstrip('.,);'))
    return urls


def parse_range(vr, patched):
    vr = (vr or '').strip()
    introduced = '0'
    m = re.match(r'>=\s*([0-9][\w.\-]*)', vr)
    if m:
        introduced = m.group(1)
    fixed = None
    if patched:
        fm = re.search(r'([0-9]+(?:\.[0-9]+)+)', patched)
        if fm:
            fixed = fm.group(1)
    return introduced, fixed


def q(v):
    return '"%s"' % v


def summary_line(summary):
    if re.search(r'^["\'\[\]{}#&*!|>%@`]|:\s|\s#', summary) or summary != summary.strip():
        return 'summary: %s' % json.dumps(summary)
    return 'summary: %s' % summary


def render_yaml(aid, num, adv):
    summary = re.sub(r'^%s\s*' % re.escape(aid), '', adv['summary']).strip()
    details = build_details(adv['description'])

    cves = []
    for c in re.findall(r'CVE-\d{4}-\d+', adv['summary'] + ' ' + adv['description']):
        if c not in cves:
            cves.append(c)

    refs = extract_refs(adv['description'])
    if not refs:
        refs = (['https://www.cve.org/CVERecord?id=%s' % c for c in cves]
                if cves else [adv['html_url']])

    date = adv.get('published_at') or adv.get('updated_at') or adv.get('created_at')

    lines = ['id: %s' % aid, summary_line(summary), 'details: |']
    for dl in details.split('\n'):
        lines.append('' if dl == '' else '  ' + dl)

    lines.append('affected:')
    for v in adv['vulnerabilities']:
        introduced, fixed = parse_range(v.get('vulnerable_version_range', ''),
                                        v.get('patched_versions', ''))
        lines += ['  - package:',
                  '      name: %s' % v['package']['name'],
                  '      ecosystem: MidnightBSD',
                  '    ranges:',
                  '      - type: ECOSYSTEM',
                  '        events:',
                  '          - introduced: %s' % q(introduced)]
        if fixed:
            lines.append('          - fixed: %s' % q(fixed))

    lines.append('references:')
    for u in refs:
        lines += ['  - type: WEB', '    url: %s' % u]

    if cves:
        lines.append('aliases:')
        lines += ['  - %s' % c for c in cves]

    lines += ['modified: %s' % q(date), 'published: %s' % q(date)]
    return '\n'.join(lines) + '\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', default='MidnightBSD/src')
    ap.add_argument('--out', default='vulns/midnightbsd')
    ap.add_argument('--latest-id', default='latest-id.txt')
    ap.add_argument('--year', type=int)
    ap.add_argument('--from', dest='lo', type=int)
    ap.add_argument('--to', dest='hi', type=int)
    ap.add_argument('--force', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    data = fetch_advisories(args.repo)

    parsed = {}  # (year, num) -> adv
    for a in data:
        if a.get('state') != 'published':
            continue
        m = re.search(r'MNBSD-(\d{4})-(\d+)', a.get('summary', ''))
        if m:
            parsed[(int(m.group(1)), int(m.group(2)))] = a

    written, skipped = [], []
    max_by_year = {}
    for (year, num), adv in sorted(parsed.items()):
        if args.year and year != args.year:
            continue
        if args.lo is not None and num < args.lo:
            continue
        if args.hi is not None and num > args.hi:
            continue
        aid = 'MNBSD-%d-%d' % (year, num)
        path = os.path.join(args.out, '%s.yaml' % aid)
        max_by_year[year] = max(max_by_year.get(year, 0), num)
        if os.path.exists(path) and not args.force:
            skipped.append(aid)
            continue
        content = render_yaml(aid, num, adv)
        if args.dry_run:
            print('--- would write %s ---' % path)
            print(content)
        else:
            with open(path, 'w') as f:
                f.write(content)
        written.append(aid)

    print('Wrote %d file(s): %s' % (len(written), ', '.join(written) or '(none)'))
    if skipped:
        print('Skipped %d existing (use --force to overwrite): %s'
              % (len(skipped), ', '.join(skipped)))

    # Update latest-id.txt to the highest ID for the most recent year seen.
    if max_by_year and not args.dry_run:
        year = max(max_by_year)
        newest = '%d-%d' % (year, max_by_year[year])
        cur = ''
        if os.path.exists(args.latest_id):
            cur = open(args.latest_id).read().strip()
        if cur != newest:
            with open(args.latest_id, 'w') as f:
                f.write(newest + '\n')
            print('Updated %s: %s -> %s' % (args.latest_id, cur or '(empty)', newest))

    if written and not args.dry_run:
        print('\nNext: python3 scripts/osvtohtml.py %s' % args.out)


if __name__ == '__main__':
    sys.exit(main())
