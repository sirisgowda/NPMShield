#!/usr/bin/env python3
"""NPMShield fusion score, gap findings and IoC extraction.

Usage:  python3 fusion.py
Reads   ../results/static_<label>.json and ../results/dynamic_<label>.json
        (label = malicious, benign) written by static_analyzer.py and sandbox_runner.py.
Writes  ../results/fusion_results.csv, iocs.csv and review2_tables.md.
Reads files only. Nothing from the samples is executed.
"""
import csv, json, os, re
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, '..', 'results'))
W_STATIC, W_DYN = 0.4, 0.6
CANARY_FLOOR = 80          # a canary credential file that was really read forces at least this score
FLAG_AT = 30               # score above this counts as flagged


def verdict(score):
    return 'low' if score <= 30 else 'suspicious' if score <= 60 else 'malicious'


SERVICES = ('npmjs.org', 'npmjs.com', 'github.com', 'githubusercontent.com', 'amazonaws.com', 'ipinfo.io',
            'ip-api.com', 'discord.com', 'discordapp.com', 'google.com', 'googleapis.com')
WEBHOOK = re.compile(r'(discord(?:app)?\.com/api/webhooks/\d+/)[\w-]+')


def redact(v):
    return WEBHOOK.sub(r'\1<redacted>', v)


def defang(v):
    return redact(v).replace('http', 'hxxp').replace('.', '[.]')


def is_service(v):
    host = v.split(':')[0]
    return host == '169.254.169.254' or any(host == x or host.endswith('.' + x) for x in SERVICES)


def category(typ, val):
    if 'discord.com/api/webhooks' in val:
        return 'attacker-controlled'
    if typ in ('domain', 'connect_target'):
        return 'legitimate service' if is_service(val) else 'attacker-controlled'
    if typ == 'url':
        h = urlparse(val.rstrip(".,;)'\"")).hostname
        return 'legitimate service' if h and is_service(h) else 'attacker-controlled'
    return 'attacker-controlled'


def load(label):
    def rd(name):
        p = os.path.join(RESULTS, name)
        return {r['sample']: r for r in json.load(open(p))} if os.path.exists(p) else {}
    return rd(f'static_{label}.json'), rd(f'dynamic_{label}.json')


def canary_read(dyn):
    """True if a canary credential file was opened successfully (not just probed) in any profile."""
    for p in dyn['profiles'].values():
        for ev in p['flags'].get('CRED_ACCESS', []):
            if '(missing)' not in ev:
                return True
    return False


def fuse(label):
    st, dy = load(label)
    rows = []
    for name in sorted(set(st) & set(dy)):
        s, d = st[name]['score'], dy[name]['dynamic_score']
        fused = round(W_STATIC * s + W_DYN * d)
        override = canary_read(dy[name])
        if override and fused < CANARY_FLOOR:
            fused = CANARY_FLOOR
        gap = ('static-clean / dynamic-flagged' if s <= FLAG_AT < d else
               'static-flagged / dynamic-clean' if d <= FLAG_AT < s else '')
        rows.append({
            'sample': name, 'label': label, 'static': s, 'dynamic': d, 'fused': fused,
            'verdict': verdict(fused), 'canary_override': override, 'gap': gap,
            'detected_with_gap_rule': fused > FLAG_AT or gap.startswith('static-clean'),
            'inert': s == 0 and d == 0,
            'static_rules': ' '.join(sorted(st[name]['hits'])),
            'dynamic_flags': ' '.join(f for f in dy[name]['flags']),
            'env_differs': dy[name].get('env_differs', False),
        })
    missing = (set(st) ^ set(dy))
    return rows, missing


def clean_url(u):
    return u.rstrip(".,;)'\"")


def host_of(u):
    h = urlparse(clean_url(u)).hostname
    return h.rstrip('.,;') if h else None


def collect_iocs(label):
    """Each IoC gets a confidence tier:
       observed      = seen in the sandbox (strace, stdout or stubbed library call)
       install-hook  = in an install script
       decoded       = base64 string decoded from the code
       code-string   = string literal inside the code (needs triage, may be a doc link or a target list)
    """
    st, dy = load(label)
    out, seen = [], set()

    def add(sample, typ, val, conf):
        val = redact(val) if val else val
        key = (sample, typ, val)
        if val and key not in seen:
            seen.add(key)
            out.append({'sample': sample, 'type': typ, 'value': val, 'confidence': conf,
                        'category': category(typ, val)})

    for name in sorted(set(st) | set(dy)):
        d = dy.get(name)
        if d:                                   # dynamic first, so 'observed' wins on duplicates
            for prof in d['profiles'].values():
                for u in prof.get('urls', []):
                    add(name, 'url', clean_url(u), 'observed')
                    add(name, 'domain', host_of(u), 'observed')
                for h in prof.get('hosts', []):
                    add(name, 'domain', h, 'observed')
                for n in prof.get('net', []):
                    add(name, 'connect_target', n, 'observed')
                for f in prof.get('files', []):
                    add(name, 'file_written', f, 'observed')
        s = st.get(name, {})
        scripts = ' '.join(str(v) for v in s.get('install_scripts', {}).values())
        for u in s.get('iocs', {}).get('urls', []):
            conf = ('hardcoded-webhook' if 'discord.com/api/webhooks' in u else
                    'install-hook' if u in scripts else 'code-string')
            add(name, 'url', clean_url(u), conf)
            add(name, 'domain', host_of(u), conf)
        for ip in s.get('iocs', {}).get('ips', []):
            add(name, 'ip', ip, 'code-string')
        for dcd in s.get('iocs', {}).get('decoded', []):
            add(name, 'decoded_string', dcd, 'decoded')
            for u in re.findall(r'https?://[^\s\'"]+', dcd):
                add(name, 'domain', host_of(u), 'decoded')
    return out


def pct(n, d):
    return f'{n}/{d} ({round(100 * n / d)}%)' if d else '0/0'


def main():
    mal, miss_m = fuse('malicious')
    ben, miss_b = fuse('benign')
    if not mal:
        raise SystemExit('No matching static and dynamic results found for malicious samples. '
                         'Run static_analyzer.py and sandbox_runner.py first.')
    for m in (miss_m | miss_b):
        print('WARNING: sample missing from static or dynamic results:', m)

    allrows = mal + ben
    print(f"{'SAMPLE':50} {'STAT':>4} {'DYN':>4} {'FUSED':>5}  {'VERDICT':10} NOTES")
    for r in allrows:
        notes = []
        if r['canary_override']:
            notes.append('CANARY-OVERRIDE')
        if r['gap']:
            notes.append('GAP: ' + r['gap'])
        if r['inert']:
            notes.append('inert (no behaviour in either stage)')
        print(f"{r['sample'][:50]:50} {r['static']:>4} {r['dynamic']:>4} {r['fused']:>5}  "
              f"{r['verdict']:10} {'; '.join(notes)}")

    n = len(mal)
    inert = sum(r['inert'] for r in mal)
    live = n - inert
    sf = sum(r['static'] > FLAG_AT for r in mal)
    df = sum(r['dynamic'] > FLAG_AT for r in mal)
    ff = sum(r['fused'] > FLAG_AT for r in mal)
    gf = sum(r['detected_with_gap_rule'] for r in mal)
    nb = len(ben)
    metrics = [
        ('Static only', sf, sum(r['static'] > FLAG_AT for r in ben)),
        ('Dynamic only', df, sum(r['dynamic'] > FLAG_AT for r in ben)),
        ('Fused score (0.4 static + 0.6 dynamic, canary override)', ff, sum(r['fused'] > FLAG_AT for r in ben)),
        ('Fused score + gap rule (dynamic-flagged gaps)', gf, sum(r['detected_with_gap_rule'] for r in ben)),
    ]
    print(f'\nMalicious samples: {n} ({inert} inert, {live} with behaviour or code that did something)')
    print(f"{'METHOD':60} {'MALICIOUS FLAGGED':>20} {'BENIGN FALSE POS':>18}")
    for name, tp, fp in metrics:
        print(f'{name:60} {pct(tp, n):>20} {pct(fp, nb):>18}')
    gaps = [r for r in allrows if r['gap']]
    print(f'\nGap findings: {len(gaps)}')
    for g in gaps:
        print(f"  {g['sample']}: static {g['static']}, dynamic {g['dynamic']}  ({g['gap']})")
    print('Samples that behaved differently between laptop and CI profiles:',
          [r['sample'] for r in allrows if r['env_differs']] or 'none')

    iocs = collect_iocs('malicious') + collect_iocs('benign')
    with open(os.path.join(RESULTS, 'fusion_results.csv'), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(allrows[0].keys()))
        w.writeheader()
        w.writerows(allrows)
    with open(os.path.join(RESULTS, 'iocs.csv'), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=['sample', 'type', 'value', 'confidence', 'category'])
        w.writeheader()
        w.writerows(iocs)

    bytype = {}
    for i in iocs:
        bytype.setdefault(i['type'], set()).add(i['value'])
    print('\nIoCs extracted (unique values): ' + ', '.join(f'{t}={len(v)}' for t, v in sorted(bytype.items())))
    high = [i for i in iocs if i['confidence'] != 'code-string']
    low = [i for i in iocs if i['confidence'] == 'code-string']
    hdom = sorted({i['value'] for i in high if i['type'] == 'domain'})
    ldom = sorted({i['value'] for i in low if i['type'] == 'domain'} - set(hdom))
    att = [i for i in high if i['category'] == 'attacker-controlled']
    svc = [i for i in high if i['category'] != 'attacker-controlled']
    print('\nATTACKER-CONTROLLED INDICATORS (high confidence):')
    for i in att:
        print(f"  {i['sample'][:42]:42} {i['type']:15} {defang(i['value'])[:78]:78} [{i['confidence']}]")
    print('\nLEGITIMATE SERVICES CONTACTED (not blocklist material, shows what the sample targets):')
    per = {}
    for i in svc:
        if i['type'] in ('domain', 'connect_target'):
            per.setdefault(i['sample'], set()).add(defang(i['value']))
    for smp, v in sorted(per.items()):
        print(f"  {smp[:42]:42} {', '.join(sorted(v))}")
    print(f'\nLOW-CONFIDENCE: {len(ldom)} more domains and {len({i["value"] for i in low if i["type"] == "ip"})} IPs '
          'are only strings inside code (doc links, target or proxy lists). See iocs.csv. Triage before reporting.')
    by_sample = {}
    for i in low:
        by_sample[i['sample']] = by_sample.get(i['sample'], 0) + 1
    print('Low-confidence count per sample:', dict(sorted(by_sample.items(), key=lambda x: -x[1])[:6]))

    dyn_all = {}
    for lab in ('malicious', 'benign'):
        dyn_all.update(load(lab)[1])
    print('\nDYNAMIC EVIDENCE (laptop profile, first two items per flag):')
    for r in allrows:
        d = dyn_all.get(r['sample'])
        if not d or not d['profiles']['laptop']['flags']:
            continue
        print(' ', r['sample'])
        for fl, ev in d['profiles']['laptop']['flags'].items():
            print(f"    {fl}: " + ' | '.join(e[:90] for e in ev[:2]))
        stubbed = sorted(set(d['profiles']['laptop'].get('stubbed', [])))
        if stubbed:
            print('    stubbed modules:', ', '.join(stubbed[:8]))

    md = ['# NPMShield Review 2 tables (generated)', '',
          '## Fused results', '',
          '| Sample | Static | Dynamic | Fused | Verdict | Notes |', '|---|---|---|---|---|---|']
    for r in allrows:
        note = '; '.join(x for x in [('canary override' if r['canary_override'] else ''), r['gap'],
                                     ('inert' if r['inert'] else '')] if x)
        md.append(f"| {r['sample']} | {r['static']} | {r['dynamic']} | {r['fused']} | {r['verdict']} | {note} |")
    md += ['', '## Detection by method', '', '| Method | Malicious flagged | Benign false positives |', '|---|---|---|']
    for name, tp, fp in metrics:
        md.append(f'| {name} | {pct(tp, n)} | {pct(fp, nb)} |')
    md += ['', '## Attacker-controlled indicators (defanged, high confidence)', '',
           '| Sample | Type | Value | Basis |', '|---|---|---|---|']
    for i in att:
        md.append(f"| {i['sample']} | {i['type']} | {defang(i['value'])} | {i['confidence']} |")
    md += ['', '## Legitimate services contacted', '', '| Sample | Services |', '|---|---|']
    for smp, v in sorted(per.items()):
        md.append(f"| {smp} | {', '.join(sorted(v))} |")
    md += ['', f'## Low-confidence strings found in code ({len(ldom)} domains)', '',
           'These are string literals inside package code (documentation links, target lists, proxy lists). '
           'They were not observed in the sandbox and need manual triage before being called indicators.', '']
    md += [f'- {defang(d)}' for d in ldom]
    open(os.path.join(RESULTS, 'review2_tables.md'), 'w').write('\n'.join(md) + '\n')
    print(f'\nSaved fusion_results.csv, iocs.csv and review2_tables.md in {RESULTS}')


if __name__ == '__main__':
    main()
