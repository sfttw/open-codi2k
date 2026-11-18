#!/usr/bin/env python3
"""Decompile an APK with JADX and package LED/motion call sites for review."""
import argparse
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

TERMS = [
    'doMotionactivateddeterrentLightGet', 'doMotionactivateddeterrentLightSet',
    'doLightGet', 'doLightSet', 'ledSet', 'ledGet',
    'motionactivateddeterrent', 'sdk_user_led',
    'motionDetect', 'motionRecord', 'recordingIndicator', 'statusLed',
]

def find_jadx(explicit):
    candidates = [explicit] if explicit else []
    candidates += [shutil.which('jadx'), shutil.which('jadx.bat')]
    for base in (Path.cwd(), Path.home() / 'Downloads', Path.home() / 'Desktop'):
        candidates += [str(p) for p in base.glob('jadx*/bin/jadx.bat')]
    for p in candidates:
        if p and Path(p).is_file():
            return str(Path(p).resolve())
    raise SystemExit('JADX CLI not found. Supply --jadx "C:\\path\\to\\jadx\\bin\\jadx.bat" (download the JADX release ZIP and extract it first).')

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--apk', default='Momentum+Secure_V1.02.18_APKPure.apk')
    ap.add_argument('--jadx', help='Full path to jadx.bat (optional if on PATH)')
    ap.add_argument('--out', default='jadx_led_export.zip')
    ap.add_argument('--workdir', default='jadx_led_work')
    ap.add_argument('--max-files', type=int, default=350)
    args = ap.parse_args()
    apk = Path(args.apk).resolve()
    if not apk.is_file():
        raise SystemExit(f'APK not found: {apk}')
    jadx = find_jadx(args.jadx)
    work = Path(args.workdir).resolve()
    src = work / 'sources'
    if not src.exists() or not any(src.rglob('*.java')):
        work.mkdir(parents=True, exist_ok=True)
        cmd = [jadx, '--no-res', '-d', str(work), str(apk)]
        print('Running JADX; this can take several minutes...', flush=True)
        if os.name == 'nt' and jadx.lower().endswith(('.bat', '.cmd')):
            cmd = ['cmd', '/c', *cmd]
        proc = subprocess.run(cmd, check=False)
        if proc.returncode:
            print(f'JADX returned {proc.returncode}; checking for partial source output.', file=sys.stderr)
    if not src.is_dir():
        raise SystemExit('No decompiled sources found. Check JADX installation and console output.')
    hits = []
    for f in src.rglob('*.java'):
        try:
            content = f.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        lines = content.splitlines()
        matched = [(i + 1, line.strip()[:300]) for i, line in enumerate(lines)
                   if any(t.lower() in line.lower() for t in TERMS)]
        if matched:
            hits.append((f, matched))
    hits.sort(key=lambda x: (-len(x[1]), str(x[0])))
    chosen = hits[:args.max_files]
    out = Path(args.out).resolve()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        index = ['JADX LED / motion call-site export', f'APK: {apk.name}',
                 f'JADX: {jadx}', f'Java files matching terms: {len(hits)}',
                 f'Java files included: {len(chosen)}', '', 'SEARCH TERMS:', *TERMS, '', 'MATCHES:']
        for f, matches in chosen:
            rel = f.relative_to(src)
            z.write(f, 'sources/' + rel.as_posix())
            index.append(f'\n{rel} ({len(matches)} matches)')
            for lineno, line in matches[:120]:
                index.append(f'  L{lineno}: {line}')
            if len(matches) > 120:
                index.append(f'  ... {len(matches) - 120} more matches in source file')
        if len(hits) > len(chosen):
            index.append(f'\nTRUNCATED: {len(hits)-len(chosen)} files omitted. Raise --max-files if needed.')
        z.writestr('INDEX.txt', '\n'.join(index) + '\n')
    print(f'Found {len(hits)} matching Java files; exported {len(chosen)}.')
    print(f'UPLOAD THIS ZIP: {out}')

if __name__ == '__main__':
    main()