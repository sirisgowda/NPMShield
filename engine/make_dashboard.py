#!/usr/bin/env python3
"""NPMShield dashboard builder.

Usage:  python3 make_dashboard.py
Reads   ../results/fusion_results.csv, review2_tables.md, dynamic_malicious.json, dynamic_benign.json
Writes  ../results/dashboard.html  (one self-contained page, open it in Firefox)
Reads result files only. Nothing from the samples is executed.
"""
import csv, html, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, '..', 'results'))
MAXLEN = 200


def esc(s):
    return html.escape(str(s), quote=True)


def clean(s):
    """Redact webhook tokens and shorten very long values."""
    s = re.sub(r'(webhooks/\d+)/[A-Za-z0-9_\-]{8,}', r'\1/<redacted>', str(s))
    m = re.match(r'^((?:hxxps?|https?)://[^/\s]+)/(\S{60,})$', s)
    if m:
        return f'{m.group(1)}/<long base64 path, {len(m.group(2))} chars>'
    if len(s) > MAXLEN:
        s = s[:MAXLEN - 12] + '...[cut]'
    return s


def read_csv(name):
    p = os.path.join(RESULTS, name)
    if not os.path.exists(p):
        raise SystemExit(f'Missing {p}. Run fusion.py first.')
    with open(p, newline='') as fh:
        return list(csv.DictReader(fh))


def read_json(name):
    p = os.path.join(RESULTS, name)
    if not os.path.exists(p):
        return []
    try:
        return json.load(open(p))
    except Exception:
        return []


def parse_md(name):
    """Return {section title: {'rows': [[cells]], 'bullets': [text]}}."""
    p = os.path.join(RESULTS, name)
    out, cur = {}, None
    if not os.path.exists(p):
        return out
    for line in open(p, errors='replace'):
        line = line.rstrip('\n')
        if line.startswith('## '):
            cur = out.setdefault(line[3:].strip(), {'rows': [], 'bullets': []})
        elif cur is not None and line.startswith('|'):
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if cells and not set(''.join(cells)) <= set('-: '):
                cur['rows'].append(cells)
        elif cur is not None and line.startswith('- '):
            cur['bullets'].append(line[2:].strip())
    return out


def section(md, prefix):
    for k, v in md.items():
        if k.startswith(prefix):
            return v
    return {'rows': [], 'bullets': []}


def table(header, rows, cls=''):
    h = ''.join(f'<th>{esc(c)}</th>' for c in header)
    b = ''.join('<tr>' + ''.join(f'<td>{esc(clean(c))}</td>' for c in r) + '</tr>' for r in rows)
    return f'<div class="scroll"><table class="{cls}"><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'


def bar(v):
    v = int(float(v or 0))
    return f'<span class="bar"><i style="width:{v}%"></i></span><b>{v}</b>'


def main():
    fusion = read_csv('fusion_results.csv')
    dyn = {r['sample']: r for r in read_json('dynamic_malicious.json') + read_json('dynamic_benign.json')}
    md = parse_md('review2_tables.md')

    mal = [r for r in fusion if r['label'] == 'malicious']
    ben = [r for r in fusion if r['label'] == 'benign']

    def rows_html(rows):
        out = []
        for r in rows:
            notes = []
            if r['canary_override'] == 'True':
                notes.append('canary override')
            if r['gap']:
                notes.append(r['gap'])
            if r['inert'] == 'True':
                notes.append('inert, no behaviour in either stage')
            out.append(
                f'<tr><td class="name">{esc(r["sample"])}</td><td>{bar(r["static"])}</td>'
                f'<td>{bar(r["dynamic"])}</td><td>{bar(r["fused"])}</td>'
                f'<td><span class="v {esc(r["verdict"])}">{esc(r["verdict"])}</span></td>'
                f'<td class="note">{esc("; ".join(notes))}</td></tr>')
        return ''.join(out)

    head = '<thead><tr><th>Sample</th><th>Static</th><th>Dynamic</th><th>Fused</th><th>Verdict</th><th>Notes</th></tr></thead>'
    fused_tbl = (f'<div class="scroll"><table class="scores">{head}'
                 f'<tbody><tr class="group"><td colspan="6">Malicious samples ({len(mal)})</td></tr>{rows_html(mal)}'
                 f'<tr class="group"><td colspan="6">Benign samples ({len(ben)})</td></tr>{rows_html(ben)}</tbody></table></div>')

    det = section(md, 'Detection by method')
    det_tbl = table(['Method', 'Malicious flagged', 'Benign false positives'], det['rows'][1:]) if det['rows'] else ''

    # gaps
    gaps_new = [r for r in fusion if r['gap'].startswith('static-clean')]
    gaps_fp = [r for r in fusion if r['gap'].startswith('static-flagged')]
    gap_html = ''.join(
        f'<li><b>{esc(r["sample"])}</b>: static {esc(r["static"])}, dynamic {esc(r["dynamic"])}. '
        f'Static called it low risk; the sandbox flagged it.</li>' for r in gaps_new)
    fp_html = ''.join(
        f'<li><b>{esc(r["sample"])}</b>: static {esc(r["static"])}, dynamic {esc(r["dynamic"])}. '
        f'Static false positive, corrected by the sandbox.</li>' for r in gaps_fp)

    # IoCs
    att = section(md, 'Attacker-controlled')
    leg = section(md, 'Legitimate services')
    low = section(md, 'Low-confidence')
    att_tbl = table(['Sample', 'Type', 'Value', 'Basis'], att['rows'][1:]) if att['rows'] else '<p>None found.</p>'
    leg_tbl = table(['Sample', 'Services'], leg['rows'][1:]) if leg['rows'] else '<p>None found.</p>'
    low_html = ''.join(f'<li>{esc(clean(b))}</li>' for b in low['bullets'])

    # evidence
    ev = []
    for r in fusion:
        d = dyn.get(r['sample'])
        if not d or not d.get('flags'):
            continue
        lap = d['profiles'].get('laptop', {})
        lines = []
        for flag, items in lap.get('flags', {}).items():
            lines.append(f'<dt>{esc(flag)}</dt><dd>{"<br>".join(esc(clean(i)) for i in items[:3])}</dd>')
        if lap.get('hosts'):
            lines.append(f'<dt>hosts</dt><dd>{esc(clean(", ".join(lap["hosts"])))}</dd>')
        if lap.get('net'):
            lines.append(f'<dt>connect targets</dt><dd>{esc(", ".join(lap["net"]))}</dd>')
        ev.append(f'<details><summary><span class="v {esc(r["verdict"])}">{esc(r["verdict"])}</span> '
                  f'{esc(r["sample"])} <em>fused {esc(r["fused"])}</em></summary><dl>{"".join(lines)}</dl></details>')

    n_gap = len(gaps_new)
    page = TEMPLATE
    for k, v in {
        '@@MAL@@': str(len(mal)), '@@BEN@@': str(len(ben)), '@@NGAP@@': str(n_gap),
        '@@FUSED@@': fused_tbl, '@@DET@@': det_tbl, '@@GAPS@@': gap_html or '<li>None.</li>',
        '@@FP@@': fp_html or '<li>None.</li>', '@@ATT@@': att_tbl, '@@LEG@@': leg_tbl,
        '@@LOW@@': low_html or '<li>None.</li>', '@@NLOW@@': str(len(low['bullets'])),
        '@@EVID@@': ''.join(ev) or '<p>No dynamic evidence found.</p>',
    }.items():
        page = page.replace(k, v)
    out = os.path.join(RESULTS, 'dashboard.html')
    open(out, 'w').write(page)
    print('Saved', out)


TEMPLATE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NPMShield results</title>
<style>
:root{--bg:#eef1f4;--panel:#fff;--ink:#16202b;--mute:#5a6775;--line:#d3dae1;--accent:#0f5c63;
--low:#2e7d4f;--sus:#b26a00;--mal:#b3261e;--lowbg:#e3f2e9;--susbg:#fbeed7;--malbg:#f9e0de}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}
h1{font:600 28px/1.2 Georgia,"Times New Roman",serif;margin:0 0 4px}
h2{font:600 19px/1.3 Georgia,"Times New Roman",serif;margin:0 0 6px;color:var(--accent)}
p.lead{color:var(--mute);margin:0 0 24px;max-width:70ch}
section{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:20px 22px;margin:0 0 18px}
section>p{color:var(--mute);margin:0 0 12px;max-width:75ch}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-weight:600;border-bottom:2px solid var(--ink);padding:6px 10px;white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
td.name{font-weight:600;min-width:260px}
td.note{color:var(--mute);font-size:13px}
tr.group td{background:var(--bg);font-weight:600;color:var(--accent)}
.bar{display:inline-block;width:70px;height:8px;background:var(--line);border-radius:4px;margin-right:8px;vertical-align:middle;overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent)}
.v{display:inline-block;padding:1px 9px;border-radius:10px;font-size:12.5px;font-weight:600}
.v.low{background:var(--lowbg);color:var(--low)}.v.suspicious{background:var(--susbg);color:var(--sus)}.v.malicious{background:var(--malbg);color:var(--mal)}
ul{margin:6px 0 0;padding-left:20px}li{margin:4px 0}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:800px){.cols{grid-template-columns:1fr}}
details{border-top:1px solid var(--line);padding:8px 0}
summary{cursor:pointer;font-weight:600}summary em{color:var(--mute);font-weight:400;font-style:normal;margin-left:8px}
summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
dl{margin:8px 0 4px 8px;display:grid;grid-template-columns:150px 1fr;gap:4px 14px;font-size:13.5px}
dt{font-weight:600;color:var(--mute)}dd{margin:0;overflow-wrap:anywhere}
.warn{border-left:4px solid var(--sus);background:var(--susbg);padding:8px 12px;margin:0 0 12px;font-size:14px}
.v{white-space:nowrap}.scores td:nth-child(n+2):nth-child(-n+5){white-space:nowrap}
</style></head><body><main>
<h1>NPMShield results</h1>
<p class="lead">@@MAL@@ malicious and @@BEN@@ benign npm packages, scored by static analysis, by a no-network sandbox run, and by a fused score (0.4 static + 0.6 dynamic, with a canary override).</p>

<section><h2>Fused results</h2>
<p>Verdict bands: low 0 to 30, suspicious 31 to 60, malicious above 60. A sample counts as flagged above 30.</p>
@@FUSED@@</section>

<section><h2>Detection by method</h2>
<p>The set is small, so these numbers show a pattern and do not prove a rate.</p>
@@DET@@</section>

<section><h2>Gap findings</h2>
<div class="cols"><div><b>Detection gaps (@@NGAP@@)</b><ul>@@GAPS@@</ul></div>
<div><b>False-positive correction</b><ul>@@FP@@</ul></div></div></section>

<section><h2>Attacker-controlled indicators</h2>
<p>Observed in the sandbox, decoded from install scripts, or hardcoded as a webhook. Webhook tokens are redacted and long values are cut.</p>
@@ATT@@</section>

<section><h2>Legitimate services contacted</h2>
<p>These show what each sample targets. Keep them off any blocklist.</p>
@@LEG@@</section>

<section><h2>Low-confidence strings</h2>
<div class="warn">@@NLOW@@ domains appear only as text inside package code (documentation links, target lists, proxy lists). Triage them before calling them indicators.</div>
<details><summary>Show the list</summary><ul>@@LOW@@</ul></details></section>

<section><h2>Sandbox evidence per sample</h2>
<p>Laptop profile, first three items per flag. Open a row to see it.</p>
@@EVID@@</section>
</main></body></html>
'''

if __name__ == '__main__':
    main()
