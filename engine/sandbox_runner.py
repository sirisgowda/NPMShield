#!/usr/bin/env python3
"""NPMShield dynamic sandbox runner.

Usage:  python3 sandbox_runner.py <folder_of_unpacked_samples> <label> [name_filter]
        label is "malicious" or "benign".
        name_filter (optional) runs only samples whose folder name contains it.

For every sample and for two profiles (laptop, ci) it starts a fresh Docker
container with NO network, plants canary credential files, then runs
  1. the install hooks (preinstall, install, postinstall)
  2. an import (require) of the package, with timers compressed
under strace. It then parses the strace logs into behaviour flags.
"""
import csv, json, os, re, subprocess, sys, tempfile, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, '..', 'results'))
IMAGE = 'npmshield-sandbox'
RUN_TIMEOUT = 120

PROFILES = {
    'laptop': {'hostname': 'dev-macbook', 'user': 'dev', 'home': '/home/dev', 'env': {}},
    'ci': {'hostname': 'runner-7f3a2c', 'user': 'runner', 'home': '/home/runner',
           'env': {'CI': 'true', 'GITHUB_ACTIONS': 'true',
                   'GITHUB_TOKEN': 'ghp_CANARY000000000000000000000000000000',
                   'NPM_TOKEN': 'npm_CANARY00000000000000000000000000',
                   'AWS_ACCESS_KEY_ID': 'AKIACANARY0000000000',
                   'AWS_SECRET_ACCESS_KEY': 'CANARYSECRET0000000000000000000000000000'}},
}

# ---------------------------------------------------------------- driver files
TRACE_SYSCALLS = ('execve,execveat,openat,open,connect,bind,listen,sendto,sendmmsg,sendmsg,'
                  'rename,renameat,renameat2,chmod,fchmodat,clone,clone3,fork,vfork')

INSIDE_SH = r'''#!/bin/sh
# Runs INSIDE the container.
mkdir -p "$HOME/.ssh" "$HOME/.aws" /work /out
echo 'nameserver 127.0.0.1' > /etc/resolv.conf 2>/dev/null || true
export PATH=/driver/bin:$PATH
echo '//registry.npmjs.org/:_authToken=npm_CANARY00000000000000000000000000' > "$HOME/.npmrc"
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'CANARYCANARYCANARYCANARY' '-----END OPENSSH PRIVATE KEY-----' > "$HOME/.ssh/id_rsa"
chmod 600 "$HOME/.ssh/id_rsa"
printf '%s\n' '[default]' 'aws_access_key_id = AKIACANARY0000000000' 'aws_secret_access_key = CANARYSECRET000000000000' > "$HOME/.aws/credentials"
echo 'https://canaryuser:ghp_CANARY000000@github.com' > "$HOME/.git-credentials"
cp -r /src /work/pkg || exit 1
cd /work/pkg || exit 1
TRACE="strace -f -ttt -s 300 -e signal=none -e trace=__SYSCALLS__"
$TRACE -o /out/install.strace sh /driver/install_phase.sh > /out/install.out 2>&1
echo "install_exit=$?" > /out/exit.txt
cd /work/pkg
$TRACE -o /out/import.strace timeout -k 2 12 node /driver/import_driver.js /work/pkg > /out/import.out 2>&1
echo "import_exit=$?" >> /out/exit.txt
'''.replace('__SYSCALLS__', TRACE_SYSCALLS)

INSTALL_PHASE_SH = r'''#!/bin/sh
cd /work/pkg
for h in preinstall install postinstall; do
  s=$(node -e '/*NPMSHIELD_DRIVER*/ try{const p=require("./package.json");process.stdout.write((p.scripts||{})[process.argv[1]]||"")}catch(e){}' "$h")
  if [ -n "$s" ]; then
    echo "[npmshield] running $h: $s" >> /out/phases.txt
    timeout -k 2 20 sh -c "$s"
  fi
done
'''

IMPORT_DRIVER_JS = r'''// Imports the package. Timers are compressed, missing modules are replaced by recording stubs.
const fs = require('fs');
const path = require('path');
const Module = require('module');
const _st = global.setTimeout;
global.setTimeout = function (f, ms, ...a) { return _st(f, Math.min(Number(ms) || 0, 50), ...a); };
const _si = global.setInterval;
global.setInterval = function (f, ms, ...a) { return _si(f, Math.max(200, Math.min(Number(ms) || 0, 1000)), ...a); };
process.on('uncaughtException', (e) => console.error('uncaught:', e && e.message));
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e && e.message));

let logged = 0;
function rec(s) {
  if (logged++ > 500) return;
  try { fs.appendFileSync('/out/stub_calls.log', String(s).slice(0, 400) + '\n'); } catch (e) {}
}
function summ(a) {
  if (typeof a === 'string') return JSON.stringify(a.slice(0, 200));
  if (typeof a === 'function') return 'fn';
  try { return JSON.stringify(a, (k, v) => (typeof v === 'function' ? 'fn' : v)).slice(0, 200); }
  catch (e) { return typeof a; }
}
function mk(p, thenable = true) {
  return new Proxy(function () {}, {
    get(t, k) {
      if (typeof k === 'symbol') return k === Symbol.toPrimitive ? () => '' : undefined;
      if (k === 'toJSON' || k === '__esModule') return undefined;
      if (k === 'prototype') return t.prototype;
      if (k === 'then') {
        if (!thenable) return undefined;
        return (res) => { try { if (typeof res === 'function') res(mk(p + '#result', false)); } catch (e) {} return mk(p + '.then()'); };
      }
      return mk(p + '.' + k);
    },
    apply(t, th, args) { rec('CALL ' + p + '(' + args.map(summ).join(', ') + ')'); return mk(p + '()'); },
    construct(t, args) { rec('CALL new ' + p + '(' + args.map(summ).join(', ') + ')'); return mk(p + '()'); },
    set() { return true; },
  });
}
const origLoad = Module._load;
Module._load = function (request) {
  try { return origLoad.apply(this, arguments); }
  catch (e) {
    const first = e && e.message ? String(e.message).split('\n')[0] : '';
    if (e && e.code === 'MODULE_NOT_FOUND' && !request.startsWith('.') && !request.startsWith('/') &&
        first.includes("'" + request + "'")) {
      rec('STUB_MODULE ' + request);
      return mk(request);
    }
    throw e;
  }
};

const root = path.resolve(process.argv[2]);
function attempt(p) {
  try { require(p); return null; }
  catch (e) { console.error('import error:', p, e && e.message ? String(e.message).split('\n')[0] : e); return e; }
}
const err = attempt(root);
if (err && err.code === 'MODULE_NOT_FOUND' && String(err.message).split('\n')[0].includes(root)) {
  let files = [];
  try { files = fs.readdirSync(root).filter((f) => /\.[cm]?js$/.test(f)).sort(); } catch (e) {}
  for (const f of files) attempt(path.join(root, f));
}
'''

# ---------------------------------------------------------------- scoring
POINTS = {
    'NETWORK_CONNECT': 40,
    'DNS_LOOKUP': 35,
    'NETWORK_INTENT': 35,
    'CRED_ACCESS': 35,
    'SUSPICIOUS_EXEC': 25,
    'DROPPED_EXEC': 25,
    'PERSISTENCE_WRITE': 25,
    'LISTEN_PORT': 20,
    'CHMOD_EXEC': 10,
    'FILE_WRITE_OUTSIDE': 10,
    'RUNS_NPM': 15,
    'ENV_DIFF': 15,
}
DESC = {
    'NETWORK_CONNECT': 'Tried to open a network connection',
    'DNS_LOOKUP': 'Tried to resolve a hostname (DNS)',
    'NETWORK_INTENT': 'Called a (stubbed) network library with a URL or request',
    'CRED_ACCESS': 'Touched a credential or secret file (canary)',
    'SUSPICIOUS_EXEC': 'Ran a tool such as curl, wget, nc, python or chmod',
    'DROPPED_EXEC': 'Executed a file from a temp or home folder',
    'PERSISTENCE_WRITE': 'Wrote to a startup or persistence location',
    'LISTEN_PORT': 'Opened a listening socket',
    'CHMOD_EXEC': 'Made a file executable outside the package',
    'FILE_WRITE_OUTSIDE': 'Wrote files outside the package folder',
    'RUNS_NPM': 'Runs npm at install or import time (self-installs or publishes)',
    'ENV_DIFF': 'Behaved differently in laptop and CI profiles',
}

# ---------------------------------------------------------------- strace parsing
LINE = re.compile(r'^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(.*))?$')
UNF = re.compile(r'^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*?)\s*<unfinished \.\.\.>\s*$')
RES = re.compile(r'^(\d+)\s+(\d+\.\d+)\s+<\.\.\. (\w+) resumed>(.*)$')
STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
URL = re.compile(r'https?://[^\s\'"`<>)\\]+')
CRED = re.compile(r'\.npmrc|/\.ssh(?:/|$)|/\.aws(?:/|$)|\.git-credentials|/\.env$|/\.kube/|'
                  r'/\.docker/config\.json|/\.config/gcloud|/\.bash_history|wallet\.dat|Login Data|\.netrc|\.pypirc')
PERSIST = re.compile(r'/\.bashrc|/\.zshrc|/\.profile|/\.bash_profile|/etc/cron|/var/spool/cron|/etc/systemd|'
                     r'/\.config/systemd|authorized_keys|/etc/rc\.local|/LaunchAgents/|/etc/profile')
DROPDIRS = ('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/root/')
SUSP_EXEC = {'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'python', 'python3', 'perl', 'ruby',
             'base64', 'crontab', 'ssh', 'scp', 'powershell', 'pwsh', 'openssl', 'xxd', 'chmod'}
SKIP_WRITE = ('/work/pkg', '/dev/', '/proc/', '/sys/', '/out/')


def dns_names(text):
    """Pull hostnames out of DNS query packets that strace printed."""
    names = []
    for s in STR.findall(text):
        try:
            b = s.encode('latin1', 'ignore').decode('unicode_escape').encode('latin1', 'ignore')
        except Exception:
            continue
        if len(b) < 17:
            continue
        i, labels = 12, []
        while i < len(b) and 0 < b[i] < 64 and i + 1 + b[i] <= len(b):
            labels.append(b[i + 1:i + 1 + b[i]].decode('ascii', 'ignore'))
            i += 1 + b[i]
        if len(labels) >= 2 and all(re.fullmatch(r'[A-Za-z0-9_-]+', l) for l in labels):
            names.append('.'.join(labels))
    return names


def join_lines(path):
    """Re-join strace <unfinished ...> and <... resumed> pairs."""
    pending, out = {}, []
    with open(path, errors='replace') as fh:
        for raw in fh:
            raw = raw.rstrip('\n')
            m = UNF.match(raw)
            if m:
                pending[m.group(1)] = (m.group(2), m.group(3), m.group(4))
                continue
            m = RES.match(raw)
            if m and m.group(1) in pending:
                ts, name, prefix = pending.pop(m.group(1))
                out.append(f'{m.group(1)} {ts} {name}({prefix}{m.group(4)}')
                continue
            out.append(raw)
    return out


def parse_strace(path, phase):
    res = {'flags': {}, 'execs': [], 'net': [], 'hosts': [], 'urls': [], 'files': []}
    if not os.path.exists(path):
        return res

    def add(flag, ev):
        lst = res['flags'].setdefault(flag, [])
        ev = f'[{phase}] {ev}'[:160]
        if ev not in lst and len(lst) < 5:
            lst.append(ev)

    cmdmap = {}
    for raw in join_lines(path):
        m = LINE.match(raw)
        if not m:
            continue
        pid, _, name, args, ret, _rest = m.groups()
        pid = int(pid)
        failed = ret.startswith('-')
        q = STR.findall(args)

        if name in ('clone', 'clone3', 'fork', 'vfork'):
            if not failed and ret not in ('?', '0'):
                cmdmap[int(ret)] = cmdmap.get(pid, '')
            continue
        owner = cmdmap.get(pid, '')
        # actions performed by npm itself (reading .npmrc, writing its logs, contacting the registry)
        # are not the package's behaviour; running npm is flagged separately as RUNS_NPM.
        if ('/usr/local/bin/np' in owner or 'npm-cli' in owner) and name not in ('execve', 'execveat'):
            continue

        if name in ('execve', 'execveat') and not failed:
            path0 = q[0] if q else ''
            mm = re.search(r'\[(.*)\]\s*,\s*(?:0x|/\*)', args)
            argv = STR.findall(mm.group(1)) if mm else []
            cmd = ' '.join(argv) or path0
            cmdmap[pid] = path0 + ' ' + cmd
            is_driver = ((path0.startswith('/driver/') and not path0.startswith('/driver/bin/')) or
                         'NPMSHIELD_DRIVER' in cmd or '/driver/install_phase.sh' in cmd or
                         '/driver/import_driver.js' in cmd)
            if is_driver:
                continue
            base = os.path.basename(path0)
            if base == 'timeout':
                continue
            if cmd[:200] not in res['execs']:
                res['execs'].append(cmd[:200])
            for u in URL.findall(cmd):
                res['urls'].append(u)
            if base in SUSP_EXEC:
                add('SUSPICIOUS_EXEC', cmd[:120])
            if base in ('npm', 'npx'):
                add('RUNS_NPM', cmd[:120])
            if path0.startswith(DROPDIRS):
                add('DROPPED_EXEC', path0)

        elif name in ('openat', 'open'):
            p = q[0] if q else ''
            if not p:
                continue
            if not p.startswith('/'):
                p = '/work/pkg/' + p
            if CRED.search(p) and not p.startswith('/work/pkg'):
                add('CRED_ACCESS', p + (' (missing)' if failed else ''))
            is_write = ('O_WRONLY' in args or 'O_RDWR' in args) and not failed
            if is_write:
                if PERSIST.search(p):
                    add('PERSISTENCE_WRITE', p)
                if not p.startswith(SKIP_WRITE):
                    add('FILE_WRITE_OUTSIDE', p)
                    if p not in res['files']:
                        res['files'].append(p)

        elif name in ('rename', 'renameat', 'renameat2') and not failed:
            for p in q:
                if PERSIST.search(p):
                    add('PERSISTENCE_WRITE', 'rename -> ' + p)

        elif name in ('chmod', 'fchmodat') and not failed:
            mode = re.search(r',\s*(0[0-7]+)\s*$', args)
            p = q[0] if q else ''
            if mode and int(mode.group(1), 8) & 0o111 and p and not p.startswith(('/work/pkg', '/out')):
                add('CHMOD_EXEC', f'{p} {mode.group(1)}')

        elif name == 'connect':
            ip = port = None
            m4 = re.search(r'sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([\d.]+)"\)', args)
            m6 = re.search(r'sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"', args)
            if m4:
                port, ip = m4.group(1), m4.group(2)
            elif m6:
                port, ip = m6.group(1), m6.group(2)
            if ip is None:
                continue
            if port == '53':
                add('DNS_LOOKUP', f'dns server {ip}')
            elif ip not in ('127.0.0.1', '::1'):
                dest = f'{ip}:{port}'
                add('NETWORK_CONNECT', dest)
                if dest not in res['net']:
                    res['net'].append(dest)

        elif name in ('sendto', 'sendmmsg', 'sendmsg'):
            for h in dns_names(args):
                add('DNS_LOOKUP', f'query {h}')
                if h not in res['hosts']:
                    res['hosts'].append(h)

        elif name == 'listen' and not failed:
            add('LISTEN_PORT', 'listen() called')

    return res


NET_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'request', 'head', 'fetch', 'connect', 'send',
               'createConnection', 'lookup'}


def parse_extra(outdir, merged):
    def add(flag, ev):
        lst = merged['flags'].setdefault(flag, [])
        if ev not in lst and len(lst) < 5:
            lst.append(ev[:160])

    for phase in ('install', 'import'):
        p = os.path.join(outdir, f'{phase}.out')
        if os.path.exists(p):
            txt = open(p, errors='replace').read()
            for m in re.finditer(r'getaddrinfo (?:EAI_AGAIN|ENOTFOUND) ([A-Za-z0-9._-]+)', txt):
                h = m.group(1)
                add('DNS_LOOKUP', f'[{phase}] resolve failed: {h}')
                if h not in merged['hosts']:
                    merged['hosts'].append(h)
    p = os.path.join(outdir, 'stub_calls.log')
    if os.path.exists(p):
        for line in open(p, errors='replace'):
            line = line.rstrip('\n')
            if line.startswith('STUB_MODULE '):
                merged['stubbed'].append(line.split(' ', 1)[1])
                continue
            m = re.match(r'CALL (?:new )?(\S+?)\((.*)\)$', line)
            if not m:
                continue
            urls = URL.findall(line)
            method = m.group(1).split('.')[-1]
            if urls or method in NET_METHODS:
                add('NETWORK_INTENT', '[import] ' + line)
            for u in urls:
                if u not in merged['urls']:
                    merged['urls'].append(u)


def merge_phases(outdir):
    merged = {'flags': {}, 'execs': [], 'net': [], 'hosts': [], 'urls': [], 'files': [], 'stubbed': []}
    for phase in ('install', 'import'):
        r = parse_strace(os.path.join(outdir, f'{phase}.strace'), phase)
        for f, ev in r['flags'].items():
            merged['flags'].setdefault(f, []).extend(ev)
        for k in ('execs', 'net', 'hosts', 'urls', 'files'):
            for v in r[k]:
                if v not in merged[k]:
                    merged[k].append(v)
    parse_extra(outdir, merged)
    return merged


# ---------------------------------------------------------------- running
def find_pkg_root(sample_dir):
    best = None
    for dp, dn, fn in os.walk(sample_dir):
        dn[:] = [d for d in dn if d != 'node_modules']
        if 'package.json' in fn and (best is None or len(dp) < len(best)):
            best = dp
    return best


STUB_TOOL = '#!/bin/sh\necho "$0 $*" >> /out/netcmds.log\nexit 0\n'


def write_drivers():
    d = tempfile.mkdtemp(prefix='npmshield_drv_')
    os.makedirs(os.path.join(d, 'bin'))
    files = (('inside.sh', INSIDE_SH), ('install_phase.sh', INSTALL_PHASE_SH),
             ('import_driver.js', IMPORT_DRIVER_JS),
             ('bin/curl', STUB_TOOL), ('bin/wget', STUB_TOOL))
    for name, text in files:
        fp = os.path.join(d, name)
        with open(fp, 'w') as fh:
            fh.write(text)
        os.chmod(fp, 0o755)
    os.chmod(d, 0o755)
    os.chmod(os.path.join(d, 'bin'), 0o755)
    return d


def run_container(root, profile, outdir, drivers):
    p = PROFILES[profile]
    os.makedirs(outdir, exist_ok=True)
    os.chmod(outdir, 0o777)
    cname = 'npmshield-' + uuid.uuid4().hex[:8]
    cmd = ['docker', 'run', '--rm', '--name', cname, '--network', 'none',
           '--hostname', p['hostname'], '--memory', '512m', '--pids-limit', '256', '--cpus', '1',
           '--cap-add', 'SYS_PTRACE', '--security-opt', 'no-new-privileges',
           '-e', f"HOME={p['home']}", '-e', f"USER={p['user']}", '-e', f"LOGNAME={p['user']}"]
    for k, v in p['env'].items():
        cmd += ['-e', f'{k}={v}']
    cmd += ['-v', f'{os.path.realpath(root)}:/src:ro', '-v', f'{drivers}:/driver:ro',
            '-v', f'{os.path.realpath(outdir)}:/out', IMAGE, 'sh', '/driver/inside.sh']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
        err = r.stderr.strip()[-300:] if r.returncode not in (0,) else ''
        return r.returncode, err
    except subprocess.TimeoutExpired:
        subprocess.run(['docker', 'kill', cname], capture_output=True)
        return 124, 'container exceeded time limit and was killed'


def verdict(score):
    return 'low' if score <= 30 else 'suspicious' if score <= 60 else 'malicious'


def load_static(label):
    p = os.path.join(RESULTS, f'static_{label}.json')
    if not os.path.exists(p):
        return {}
    try:
        return {r['sample']: r['score'] for r in json.load(open(p))}
    except Exception:
        return {}


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    folder, label = sys.argv[1], sys.argv[2]
    only = sys.argv[3] if len(sys.argv) > 3 else None
    static = load_static(label)
    drivers = write_drivers()
    reports = []
    for name in sorted(os.listdir(folder)):
        sd = os.path.join(folder, name)
        if not os.path.isdir(sd) or (only and only not in name):
            continue
        root = find_pkg_root(sd)
        if not root:
            print(f'{name}: no package.json, skipped')
            continue
        rep = {'sample': name, 'label': label, 'root': root, 'profiles': {}, 'warnings': []}
        for prof in PROFILES:
            outdir = os.path.join(RESULTS, 'dynamic', label, name, prof)
            rc, err = run_container(root, prof, outdir, drivers)
            sizes = [os.path.getsize(os.path.join(outdir, f)) if os.path.exists(os.path.join(outdir, f)) else 0
                     for f in ('install.strace', 'import.strace')]
            if rc != 0 or sum(sizes) == 0:
                rep['warnings'].append(f'{prof}: docker rc={rc} trace_bytes={sizes} {err}')
            rep['profiles'][prof] = merge_phases(outdir)
            rep['profiles'][prof]['exit'] = open(os.path.join(outdir, 'exit.txt')).read().split() \
                if os.path.exists(os.path.join(outdir, 'exit.txt')) else []
        fl = {p: set(v['flags']) for p, v in rep['profiles'].items()}
        union = set().union(*fl.values())
        differs = fl['laptop'] != fl['ci']
        rep['env_differs'] = differs
        rep['diff_flags'] = sorted(fl['laptop'] ^ fl['ci'])
        if differs:
            union.add('ENV_DIFF')
        rep['flags'] = sorted(union)
        rep['dynamic_score'] = min(100, sum(POINTS[f] for f in union))
        rep['dynamic_verdict'] = verdict(rep['dynamic_score'])
        rep['static_score'] = static.get(name)
        s, d = rep['static_score'], rep['dynamic_score']
        rep['gap'] = ('STATIC-CLEAN, DYNAMIC-FLAGGED' if s is not None and s <= 30 and d > 30 else
                      'STATIC-ONLY' if s is not None and s > 30 and d <= 30 else '')
        reports.append(rep)
        print(f"{name[:46]:46} dyn={d:>3} {rep['dynamic_verdict']:10} "
              f"static={'-' if s is None else s:>3}  {' '.join(rep['flags']) or '(no behaviour)'}"
              f"{'  <<' + rep['gap'] if rep['gap'] else ''}")
        for w in rep['warnings']:
            print('   WARNING:', w)

    os.makedirs(RESULTS, exist_ok=True)
    tag = f'{label}_test' if only else label
    json.dump(reports, open(os.path.join(RESULTS, f'dynamic_{tag}.json'), 'w'), indent=2)
    with open(os.path.join(RESULTS, f'dynamic_{tag}.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['sample', 'label', 'static', 'dynamic', 'verdict', 'env_differs', 'gap', 'flags'])
        for r in reports:
            w.writerow([r['sample'], label, r['static_score'], r['dynamic_score'], r['dynamic_verdict'],
                        r['env_differs'], r['gap'], ' '.join(r['flags'])])
    print(f'\nSaved dynamic_{tag}.json and .csv in {RESULTS}')
    print('Raw strace logs: ' + os.path.join(RESULTS, 'dynamic', label))


if __name__ == '__main__':
    main()
