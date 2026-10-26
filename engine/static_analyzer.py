#!/usr/bin/env python3
"""NPMShield static analyzer.

Usage:  python3 static_analyzer.py <folder_of_unpacked_samples> <label>
        label is "malicious" or "benign" (only used in the report).

Reads files only. Nothing from the samples is ever executed.
"""
import base64, collections, csv, json, math, os, re, subprocess, sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ENGINE, '..', 'results')
MAX_FILE = 2_000_000  # skip JS files larger than 2 MB

SENSITIVE = re.compile(r'\.npmrc|\.ssh|id_rsa|\.aws|\.git-credentials|/etc/passwd|/etc/shadow|'
                       r'[/\'\"`]\.env\b|wallet\.dat|Login Data|keychain|credentials', re.I)
PERSIST = re.compile(r'crontab|\.bashrc|\.zshrc|\.profile|systemctl|LaunchAgents|authorized_keys|rc\.local')
MINER = re.compile(r'xmrig|stratum\+tcp|cryptonight|monero|minerd|coinhive', re.I)
SHELL = re.compile(r'/bin/(?:ba)?sh|cmd\.exe|powershell', re.I)
URL = re.compile(r'https?://[^\s\'"`<>)\\]+')
IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
B64 = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')
OBF_ID = re.compile(r'_0x[0-9a-f]{4,}')
HEX_ESC = re.compile(r'\\x[0-9a-fA-F]{2}')
BENIGN_HOSTS = ('github.com', 'npmjs.org', 'npmjs.com', 'w3.org', 'nodejs.org', 'mozilla.org',
                'example.com', 'apache.org', 'opensource.org', 'creativecommons.org',
                'wikipedia.org', 'mit-license.org', 'json-schema.org', 'ietf.org', 'stackoverflow.com',
                'localhost', 'gnu.org', 'typescriptlang.org', 'tc39.es')
NET_MODS = {'http', 'https', 'net', 'dns', 'tls', 'dgram', 'http2', 'node:http', 'node:https', 'node:net'}
CP_MODS = {'child_process', 'node:child_process'}
HOOKS = ('preinstall', 'install', 'postinstall')

# rule id -> (points, description). Each rule counts once per package.
RULES = {
    'INSTALL_HOOK':    (20, 'Package runs a script automatically at install time'),
    'INSTALL_NET':     (25, 'Install script contacts the network (curl, wget or a URL)'),
    'INSTALL_INLINE':  (15, 'Install script runs inline code (node -e)'),
    'INSTALL_B64':     (10, 'Install script contains base64'),
    'CHILD_PROCESS':   (15, 'Uses child_process to run commands'),
    'EVAL':            (15, 'Uses eval or new Function'),
    'NET_MODULE':      (10, 'Imports a low-level network module'),
    'SENSITIVE_PATH':  (20, 'References credential or secret file paths'),
    'ENV_ACCESS':      (5,  'Reads process.env'),
    'ENV_DUMP':        (15, 'Dumps the whole environment'),
    'HOST_FINGERPRINT': (10, 'Collects hostname, user or network details'),
    'BASE64_DECODE':   (10, 'Decodes base64 at runtime'),
    'HIGH_ENTROPY':    (10, 'Contains long high-entropy strings'),
    'OBFUSCATION':     (15, 'Shows obfuscation markers'),
    'PARSE_FAIL':      (5,  'JavaScript could not be parsed (minified or obfuscated)'),
    'HARDCODED_URL_IP': (10, 'Contains hardcoded non-trivial URLs or IPs'),
    'DROP_EXEC':       (15, 'Writes a file and changes its permissions'),
    'PERSISTENCE':     (15, 'References persistence locations'),
    'MINER':           (25, 'References cryptomining indicators'),
    'REVERSE_SHELL':   (20, 'Combines network, child_process and a shell path'),
}


def entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def find_pkg_root(sample_dir):
    best = None
    for dp, dn, fn in os.walk(sample_dir):
        dn[:] = [d for d in dn if d != 'node_modules']
        if 'package.json' in fn:
            if best is None or len(dp) < len(best):
                best = dp
    return best


def js_files(root):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d != 'node_modules']
        for f in fn:
            if f.endswith(('.js', '.cjs', '.mjs')):
                p = os.path.join(dp, f)
                if os.path.getsize(p) <= MAX_FILE:
                    out.append(p)
    return out


def run_ast(files):
    if not files:
        return []
    res = []
    for i in range(0, len(files), 100):
        chunk = files[i:i + 100]
        try:
            r = subprocess.run(['node', os.path.join(ENGINE, 'ast_scan.js')],
                               input='\n'.join(chunk), capture_output=True, text=True, timeout=120)
            res.extend(json.loads(r.stdout))
        except Exception as e:
            res.extend({'file': f, 'parsed': False, 'error': str(e), 'requires': [], 'calls': [], 'strings': []}
                       for f in chunk)
    return res


def decode_b64_tokens(text):
    found = []
    for tok in set(B64.findall(text)):
        try:
            d = base64.b64decode(tok + '=' * (-len(tok) % 4), validate=False).decode('ascii')
        except Exception:
            continue
        if d.isprintable() and (URL.search(d) or IP.search(d) or '/' in d or '.' in d) and len(d) >= 8:
            found.append(d)
    return found


def good_url(u):
    return not any(h in u for h in BENIGN_HOSTS)


def analyze(sample_dir):
    root = find_pkg_root(sample_dir)
    rep = {'sample': os.path.basename(sample_dir), 'root': root, 'name': '', 'version': '',
           'install_scripts': {}, 'hits': {}, 'iocs': {'urls': [], 'ips': [], 'decoded': []},
           'files_scanned': 0, 'parse_failures': 0}
    if not root:
        rep.update(score=0, verdict='no package.json')
        return rep
    try:
        pj = json.load(open(os.path.join(root, 'package.json'), encoding='utf8', errors='replace'))
    except Exception:
        pj = {}
    rep['name'], rep['version'] = pj.get('name', ''), pj.get('version', '')
    scripts = pj.get('scripts') or {}
    hits = rep['hits']

    def hit(rule, evidence):
        hits.setdefault(rule, [])
        if evidence and evidence not in hits[rule] and len(hits[rule]) < 3:
            hits[rule].append(str(evidence)[:140])
        elif not hits[rule] and not evidence:
            hits[rule].append('')

    # 1. install scripts
    for h in HOOKS:
        if h in scripts:
            s = str(scripts[h])
            rep['install_scripts'][h] = s[:300]
            hit('INSTALL_HOOK', f'{h}: {s[:80]}')
            if re.search(r'curl|wget|https?://|Invoke-WebRequest', s, re.I):
                hit('INSTALL_NET', f'{h}: {s[:80]}')
            if re.search(r'node\s+-[ep]\b', s):
                hit('INSTALL_INLINE', f'{h}: {s[:80]}')
            if re.search(r'base64|atob|Buffer\.from', s, re.I):
                hit('INSTALL_B64', f'{h}: {s[:80]}')
            for d in decode_b64_tokens(s):
                rep['iocs']['decoded'].append(d)
            for u in URL.findall(s):
                if good_url(u):
                    rep['iocs']['urls'].append(u)

    # 2. code
    files = js_files(root)
    rep['files_scanned'] = len(files)
    ast = {a['file']: a for a in run_ast(files)}
    for f in files:
        try:
            text = open(f, encoding='utf8', errors='replace').read()
        except Exception:
            continue
        rel = os.path.relpath(f, root)
        a = ast.get(f, {'parsed': False, 'requires': [], 'calls': [], 'strings': []})
        req, calls, strings = set(a['requires']), set(a['calls']), a['strings']
        if not a['parsed']:
            # fallback: regex on raw text so obfuscated files are still checked
            req |= set(re.findall(r'require\(\s*[\'"]([^\'"]+)[\'"]\s*\)', text))
            calls |= set(re.findall(r'\b(eval|chmodSync|chmod|writeFileSync|writeFile)\s*\(', text))
            if re.search(r'new\s+Function\s*\(', text):
                calls.add('new Function')
            rep['parse_failures'] += 1
            hit('PARSE_FAIL', rel)
        if req & CP_MODS:
            hit('CHILD_PROCESS', rel)
        if 'eval' in calls or 'new Function' in calls:
            hit('EVAL', rel)
        if req & NET_MODS:
            hit('NET_MODULE', f'{rel}: {sorted(req & NET_MODS)}')
        if 'process.env' in calls or re.search(r'process\.env', text):
            hit('ENV_ACCESS', rel)
        if re.search(r'JSON\.stringify\(\s*process\.env|Object\.(?:keys|entries|values)\(\s*process\.env', text):
            hit('ENV_DUMP', rel)
        if re.search(r'hostname|userInfo|networkInterfaces', text) and ('os' in req or 'node:os' in req):
            hit('HOST_FINGERPRINT', rel)
        if re.search(r'base64|atob\(', text):
            hit('BASE64_DECODE', rel)
        if SENSITIVE.search(text):
            m = SENSITIVE.search(text)
            hit('SENSITIVE_PATH', f'{rel}: {m.group(0)}')
        if PERSIST.search(text):
            hit('PERSISTENCE', f'{rel}: {PERSIST.search(text).group(0)}')
        if MINER.search(text):
            hit('MINER', f'{rel}: {MINER.search(text).group(0)}')
        if (req & CP_MODS) and (req & NET_MODS) and SHELL.search(text):
            hit('REVERSE_SHELL', rel)
        if ({'chmod', 'chmodSync'} & calls) and ({'writeFile', 'writeFileSync', 'createWriteStream'} & calls):
            hit('DROP_EXEC', rel)
        long_line = max((len(l) for l in text.split('\n')), default=0)
        if (len(OBF_ID.findall(text)) > 20 or len(HEX_ESC.findall(text)) > 200 or long_line > 5000):
            hit('OBFUSCATION', f'{rel} (longest line {long_line})')
        pool = strings if a['parsed'] else re.findall(r'["\']([^"\'\n]{40,})["\']', text)
        for s in pool:
            if len(s) >= 40 and ' ' not in s and not s.startswith(('http', '/', '.')) and entropy(s) >= 4.5:
                hit('HIGH_ENTROPY', f'{rel}: {s[:40]}...')
                break
        for s in pool:
            for u in URL.findall(s):
                if good_url(u):
                    rep['iocs']['urls'].append(u)
            for ip in IP.findall(s):
                if not ip.startswith(('0.', '127.', '255.')) and all(int(x) < 256 for x in ip.split('.')):
                    rep['iocs']['ips'].append(ip)
            for d in decode_b64_tokens(s):
                rep['iocs']['decoded'].append(d)

    for k in ('urls', 'ips', 'decoded'):
        rep['iocs'][k] = sorted(set(rep['iocs'][k]))[:20]
    if rep['iocs']['urls'] or rep['iocs']['ips'] or rep['iocs']['decoded']:
        hit('HARDCODED_URL_IP', (rep['iocs']['urls'] + rep['iocs']['ips'] + rep['iocs']['decoded'])[0])

    score = min(100, sum(RULES[r][0] for r in hits))
    rep['score'] = score
    rep['verdict'] = 'low' if score <= 30 else 'suspicious' if score <= 60 else 'malicious'
    return rep


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    folder, label = sys.argv[1], sys.argv[2]
    os.makedirs(RESULTS, exist_ok=True)
    reports = []
    for name in sorted(os.listdir(folder)):
        d = os.path.join(folder, name)
        if os.path.isdir(d):
            r = analyze(d)
            r['label'] = label
            reports.append(r)
    out_json = os.path.join(RESULTS, f'static_{label}.json')
    json.dump(reports, open(out_json, 'w'), indent=2)
    with open(os.path.join(RESULTS, f'static_{label}.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['sample', 'label', 'score', 'verdict', 'rules'])
        for r in reports:
            w.writerow([r['sample'], label, r['score'], r['verdict'], ' '.join(sorted(r['hits']))])
    print(f"{'SAMPLE':52} {'SCORE':>5}  {'VERDICT':10} RULES")
    for r in reports:
        print(f"{r['sample'][:52]:52} {r['score']:>5}  {r['verdict']:10} {' '.join(sorted(r['hits']))}")
    print(f'\nSaved {out_json}')


if __name__ == '__main__':
    main()
