#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_toc.py — Generate a Markdown TOC between <!-- toc --> ... <!-- tocstop -->

Usage:
  python3 scripts/gen_toc.py README.md README-ES.md --maxlevel 4

- No external deps (pure Python).
- GitHub-like anchor slugs (best-effort): lowercased, spaces->-, removed punctuation, deduped with counters.
- Only updates the block between the markers; leaves the rest of the file intact.
"""
import argparse
import re
from pathlib import Path
from typing import List, Tuple

OPEN = "<!-- toc -->"
CLOSE = "<!-- tocstop -->"
HRE = re.compile(r'^(?P<hashes>#{1,6})\s+(?P<title>.+?)\s*$')

def slugify_github(title: str, used: dict) -> str:
    # mimic GitHub anchor slugs (approximate)
    s = title.strip().lower()
    # remove markdown inlines like code spans/backticks
    s = re.sub(r'`([^`]+)`', r'\1', s)
    # remove non-alnum except spaces and hyphens
    s = re.sub(r'[^a-z0-9\s\-]', '', s)
    # spaces -> hyphens
    s = re.sub(r'\s+', '-', s).strip('-')
    # collapse multiple dashes
    s = re.sub(r'-{2,}', '-', s)
    # dedupe
    if s in used:
        used[s] += 1
        s = f"{s}-{used[s]}"
    else:
        used[s] = 0
    return s

def extract_headings(lines: List[str], maxlevel: int) -> List[Tuple[int, str, str]]:
    result = []
    used = {}
    for line in lines:
        m = HRE.match(line.rstrip())
        if not m:
            continue
        level = len(m.group('hashes'))
        if level > maxlevel:
            continue
        title = m.group('title').strip()
        # ignore top title (level 1) if it's the first line; keep others
        result.append((level, title, slugify_github(title, used)))
    return result

def build_toc(headings: List[Tuple[int, str, str]]) -> List[str]:
    out = []
    base_level = min((lvl for (lvl, _, _) in headings), default=2)
    for lvl, title, slug in headings:
        indent = '  ' * (max(lvl - base_level, 0))
        out.append(f"{indent}- [{title}](#{slug})")
    return out

def update_file(path: Path, maxlevel: int) -> bool:
    text = path.read_text(encoding='utf-8')
    if OPEN not in text or CLOSE not in text:
        return False
    pre, rest = text.split(OPEN, 1)
    mid, post = rest.split(CLOSE, 1)
    lines = text.splitlines()
    headings = extract_headings(lines, maxlevel=maxlevel)
    toc_lines = build_toc(headings)
    new_mid = '\n' + '\n'.join(toc_lines) + '\n'
    updated = pre + OPEN + new_mid + CLOSE + post
    if updated != text:
        path.write_text(updated, encoding='utf-8')
        return True
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+', help='Markdown files')
    ap.add_argument('--maxlevel', type=int, default=4, help='Max heading level to include')
    args = ap.parse_args()
    changed = False
    for f in args.files:
        p = Path(f)
        if not p.exists():
            print(f"[WARN] File not found: {p}")
            continue
        if update_file(p, maxlevel=args.maxlevel):
            print(f"[OK] TOC updated: {p}")
            changed = True
        else:
            print(f"[=] TOC unchanged or markers missing: {p}")
    return 0 if changed else 0

if __name__ == "__main__":
    raise SystemExit(main())

