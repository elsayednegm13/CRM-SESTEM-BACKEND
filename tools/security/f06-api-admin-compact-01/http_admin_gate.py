"""Bounded real Laravel HTTP gate for A5 direct permission mutation."""
import json
import pathlib
import socket
import subprocess
import sys
import time
import urllib.parse

import bootstrap as b

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
state = json.loads((runtime / 'state.json').read_text(encoding='utf-8'))
if (state['control'], state['stage'], state['db'], state['port']) != (b.CONTROL, 'fixtures_installed', b.DB, b.PORT):
    raise RuntimeError('Sandbox state mismatch')
container = state['container']
meta = json.loads(b.call(['docker', 'container', 'inspect', container]).stdout)[0]
control = b.call(['docker', 'exec', '-u', 'postgres', container, 'pg_controldata', '/var/lib/postgresql/data']).stdout
if meta['Config']['Labels'].get('control') != b.CONTROL or not meta['State']['Running'] or str(state['system_identifier']) not in control:
    raise RuntimeError('Sandbox ownership mismatch')
passwords = json.loads((runtime / 'secrets.json').read_text(encoding='utf-8'))
RUN = time.strftime('%Y%m%dT%H%M%S')
HOST = 'tenant-a.f06i03.localhost'
HOST_B = 'tenant-b.f06i03.localhost'
TARGET = 'a1111111-0000-0000-0000-00000000a004'
BASE = '/api/v1/company/staff/' + TARGET + '/permissions'
FP = "SELECT md5(string_agg(k||':'||v,'|' ORDER BY k,v)) FROM (SELECT 'd' k,to_jsonb(x)::text v FROM public.tenant_staff_permission_grants x UNION ALL SELECT 'm',to_jsonb(x)::text FROM public.tenant_staff_memberships x UNION ALL SELECT 'e',to_jsonb(x)::text FROM public.tenant_staff_security_events x) q"
baseline = b.pg_query(container, FP)
if b.pg_query(container, f"SELECT count(*) FROM public.tenant_staff_permission_grants WHERE membership_id='{TARGET}' AND permission_key='leads.view' AND scope='SELF'") != '0':
    raise RuntimeError('Target baseline grant exists')
if b.pg_query(container, 'SELECT count(*) FROM public.tenant_staff_security_events') != '0':
    raise RuntimeError('Audit baseline not empty')
version = b.pg_query(container, f"SELECT authorization_version FROM public.tenant_staff_memberships WHERE id='{TARGET}'")
updated = b.pg_query(container, f"SELECT quote_literal(updated_at::text) FROM public.tenant_staff_memberships WHERE id='{TARGET}'")
results = []


def port_free(port):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port))


def request(flag, who, method, path, payload=None, csrf=None, host=HOST):
    stem = runtime / f'wire_{RUN}_{flag}_{who}'
    jar, headers, body = [pathlib.Path(str(stem) + ext) for ext in ('.jar', '.headers', '.body')]
    argv = ['curl.exe', '--noproxy', '*', '-k', '-sS', '--max-time', '15', '--resolve', f'{host}:18112:127.0.0.1',
            '-D', str(headers), '-o', str(body), '-w', '%{http_code}', '-X', method,
            '-H', 'Accept: application/json', '-H', f'Origin: https://{host}:18112', '-b', str(jar), '-c', str(jar)]
    if csrf:
        csrf_file = pathlib.Path(str(stem) + '.csrf.header')
        csrf_file.write_text('X-XSRF-TOKEN: ' + csrf + '\n', encoding='utf-8')
        argv.extend(['-H', '@' + str(csrf_file)])
    if payload is not None:
        data_file = pathlib.Path(str(stem) + '.request.json')
        data_file.write_text(json.dumps(payload), encoding='utf-8')
        argv.extend(['-H', 'Content-Type: application/json', '--data-binary', '@' + str(data_file)])
    argv.append(f'https://{host}:18112{path}')
    p = subprocess.run(argv, cwd=b.API, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f'curl rc={p.returncode} for {flag}/{who}/{method}')
    try:
        parsed = json.loads(body.read_text(encoding='utf-8'))
    except (ValueError, OSError):
        parsed = None
    return int(p.stdout.strip()), parsed, jar


def token(jar):
    for line in jar.read_text(encoding='utf-8').splitlines():
        if line and (not line.startswith('#') or line.startswith('#HttpOnly_')):
            parts = line.split('\t')
            if len(parts) >= 7 and parts[-2] == 'XSRF-TOKEN':
                return urllib.parse.unquote(parts[-1])
    raise RuntimeError('CSRF cookie absent')


def login(flag, who, host=HOST):
    status, _, jar = request(flag, who, 'GET', '/sanctum/csrf-cookie', host=host)
    if status not in (200, 204):
        raise RuntimeError(f'CSRF bootstrap {flag}/{who} status={status}')
    tenant = 'b' if host == HOST_B else 'a'
    status, _, jar = request(flag, who, 'POST', '/api/v1/auth/login',
                             {'email': f'{who.lower()}@tenant-{tenant}.sandbox', 'password': passwords['login_' + who.lower()]}, token(jar), host=host)
    if status != 200:
        raise RuntimeError(f'Login {flag}/{who} status={status}')
    status, _, jar = request(flag, who, 'GET', '/sanctum/csrf-cookie', host=host)
    if status not in (200, 204):
        raise RuntimeError('Post login CSRF failed')
    return token(jar)


def start(flag, missing_a5=False):
    env = b.php_env(runtime, passwords, flag=(flag == 'ON' or missing_a5))
    if missing_a5:
        env.pop('F06_ACTOR_PW_A5', None)
    env['APP_URL'] = f'https://{HOST}:18112'
    env['CORS_ALLOWED_ORIGINS'] = f'https://{HOST}:18112,https://{HOST_B}:18112'
    env['SANCTUM_STATEFUL_DOMAINS'] = f'{HOST}:18112,{HOST_B}:18112'
    env['CACHE_PREFIX'] = f'f06_team01_{RUN}_{flag.lower()}'
    storage = runtime / f'storage_{RUN}_{flag.lower()}'
    for sub in ('framework/sessions', 'framework/cache/data', 'framework/views', 'logs'):
        (storage / sub).mkdir(parents=True, exist_ok=True)
    env['LARAVEL_STORAGE_PATH'] = str(storage)
    server_log = (runtime / f'server_{RUN}_{flag}.raw.log').open('w', encoding='utf-8')
    server = subprocess.Popen([str(b.PHP), 'artisan', 'serve', '--no-reload', '--host=127.0.0.1', '--port=18111'],
                              cwd=b.API, env=env, stdout=server_log, stderr=subprocess.STDOUT)
    proxy_log = (runtime / f'proxy_{RUN}_{flag}.raw.log').open('w', encoding='utf-8')
    proxy = subprocess.Popen([sys.executable, str(b.SRC / 'tls_proxy.py'), str(runtime)],
                             cwd=b.API, stdout=proxy_log, stderr=subprocess.STDOUT)
    for port, proc in ((18111, server), (18112, proxy)):
        for _ in range(150):
            if proc.poll() is not None:
                raise RuntimeError(f'Owned server exited before ready port={port}')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError(f'Owned server not ready port={port}')
    return server, server_log, proxy, proxy_log


def stop(processes):
    server, server_log, proxy, proxy_log = processes
    for proc in (proxy, server):
        if proc.poll() is None:
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True, text=True)
        proc.wait(timeout=10)
    server_log.close()
    proxy_log.close()


def check(flag, name, got, expected):
    status, data = got
    shape = data.get('data') if isinstance(data, dict) else None
    summary = {'flag': flag, 'case': name, 'status': status,
               'data': shape if isinstance(shape, dict) and set(shape) <= {'status'} else None,
               'body_keys': sorted(data) if isinstance(data, dict) else None}
    results.append(summary)
    print(f'{flag}-{name}: status={status}', flush=True)
    if status != expected:
        raise RuntimeError(f'HTTP mismatch {flag}/{name}: {status} expected {expected}')


def state_count():
    q = (f"SELECT (SELECT count(*) FROM public.tenant_staff_permission_grants WHERE membership_id='{TARGET}' AND permission_key='leads.view' AND scope='SELF'),"
         f"(SELECT count(*) FROM public.tenant_staff_permission_grants WHERE membership_id='{TARGET}' AND permission_key='leads.view' AND scope='SELF' AND revoked_at IS NULL),"
         f"(SELECT authorization_version FROM public.tenant_staff_memberships WHERE id='{TARGET}'),"
         '(SELECT count(*) FROM public.tenant_staff_security_events)')
    return list(map(int, b.pg_query(container, q).split('|')))


def reset():
    # The baseline was empty for these two test tables; restore only this round's synthetic writes.
    sql = ("BEGIN; ALTER TABLE public.tenant_staff_security_events DISABLE TRIGGER USER; "
           "ALTER TABLE public.tenant_staff_permission_grants DISABLE TRIGGER USER; "
           "DELETE FROM public.tenant_staff_security_events; "
           f"DELETE FROM public.tenant_staff_permission_grants WHERE membership_id='{TARGET}' AND permission_key='leads.view' AND scope='SELF'; "
           f"UPDATE public.tenant_staff_memberships SET authorization_version={version}, updated_at={updated} WHERE id='{TARGET}'; "
           "ALTER TABLE public.tenant_staff_permission_grants ENABLE TRIGGER USER; "
           "ALTER TABLE public.tenant_staff_security_events ENABLE TRIGGER USER; COMMIT;")
    b.sql(container, sql)
    if b.pg_query(container, FP) != baseline:
        raise RuntimeError('Fixture restoration fingerprint drift')


def run(flag):
    processes = start(flag)
    try:
        csrf = login(flag, 'A5')
        check(flag, 'A5_LOGIN', (200, {'data': {'status': 'LOGIN_OK'}}), 200)
        for name, path in (('ROLES_READ', '/api/v1/company/roles'),
                           ('STAFF_READ', '/api/v1/company/staff')):
            status, data, _ = request(flag, 'A5', 'GET', path)
            check(flag, name, (status, data), 200)
            rows = data.get('data', {}).get('roles') if name == 'ROLES_READ' and isinstance(data, dict) else data.get('data') if isinstance(data, dict) else None
            if not isinstance(rows, list) or not rows:
                raise RuntimeError(f'Admin read body mismatch {flag}/{name}')
        assert state_count() == [0, 0, int(version), 0]
        status, data, _ = request(flag, 'A5', 'POST', BASE, {'permission': 'leads.view', 'scope': 'SELF'}, csrf)
        check(flag, 'GRANT', (status, data), 201)
        if not isinstance(data, dict) or data.get('data', {}).get('status') != 'GRANTED':
            raise RuntimeError('Grant response body mismatch')
        granted = state_count()
        if granted != [1, 1, int(version) + 1, 1]:
            raise RuntimeError(f'Grant state mismatch {granted}')
        status, data, _ = request(flag, 'A5', 'POST', BASE,
                                  {'permission': 'leads.view', 'scope': 'SELF'}, csrf)
        check(flag, 'REPEAT_GRANT', (status, data), 403)
        if state_count() != granted:
            raise RuntimeError('Repeated grant changed authority')
        status, data, _ = request(flag, 'A5', 'DELETE', BASE + '/leads.view?scope=SELF', csrf=csrf)
        check(flag, 'REVOKE', (status, data), 200)
        if not isinstance(data, dict) or data.get('data', {}).get('status') != 'REVOKED':
            raise RuntimeError('Revoke response body mismatch')
        revoked = state_count()
        if revoked != [1, 0, int(version) + 2, 2]:
            raise RuntimeError(f'Revoke state mismatch {revoked}')
        audit = b.pg_query(container, "SELECT string_agg(event_type,',' ORDER BY occurred_at) FROM public.tenant_staff_security_events")
        if audit != 'tenant_staff.permission_granted,tenant_staff.permission_revoked':
            raise RuntimeError('Audit event type/order mismatch')
        audit_contract = b.pg_query(container, "SELECT count(*) FROM public.tenant_staff_security_events WHERE tenant_id='11111111-1111-1111-1111-111111111111' AND actor_membership_id='a1111111-0000-0000-0000-00000000a005' AND target_staff_user_id='aaaaaaa4-0000-0000-0000-000000000004' AND target_role_id IS NULL AND outcome='SUCCESS' AND request_id IS NULL AND metadata='{}'::jsonb")
        grant_contract = b.pg_query(container, f"SELECT count(*) FROM public.tenant_staff_permission_grants WHERE membership_id='{TARGET}' AND permission_key='leads.view' AND scope='SELF' AND granted_by_membership_id='a1111111-0000-0000-0000-00000000a005' AND revoked_by_membership_id='a1111111-0000-0000-0000-00000000a005' AND granted_at IS NOT NULL AND revoked_at IS NOT NULL")
        if audit_contract != '2' or grant_contract != '1':
            raise RuntimeError('Audit/grant actor and target contract mismatch')
        deny_cases = [
            ('A5_SELF', 'A5', 'POST', '/api/v1/company/staff/a1111111-0000-0000-0000-00000000a005/permissions', {'permission': 'leads.view', 'scope': 'SELF'}),
            ('A5_NONDELEGABLE', 'A5', 'POST', BASE, {'permission': 'company.administer', 'scope': 'ALL_TENANT'}),
            ('A5_OVER_SCOPE', 'A5', 'POST', BASE, {'permission': 'leads.view', 'scope': 'ALL_TENANT'}),
            ('A5_B_TARGET', 'A5', 'POST', '/api/v1/company/staff/b1111111-0000-0000-0000-00000000b001/permissions', {'permission': 'leads.view', 'scope': 'SELF'}),
            ('A5_SUSPENDED', 'A5', 'POST', '/api/v1/company/staff/a1111111-0000-0000-0000-00000000a003/permissions', {'permission': 'leads.view', 'scope': 'SELF'}),
            ('A5_REPEAT_REVOKE', 'A5', 'DELETE', BASE + '/leads.view?scope=SELF', None),
        ]
        for who in ('A1', 'A2', 'A4'):
            login(flag, who)
            deny_cases.append((who + '_NO_MEMBER_MANAGE', who, 'POST', BASE, {'permission': 'leads.view', 'scope': 'SELF'}))
        for name, who, method, path, payload in deny_cases:
            xsrf = csrf if who == 'A5' else token(runtime / f'wire_{RUN}_{flag}_{who}.jar')
            status, data, _ = request(flag, who, method, path, payload, xsrf)
            check(flag, name, (status, data), 403)
            if state_count() != revoked:
                raise RuntimeError(f'Negative request changed authority: {name}')
        login(flag, 'B1', host=HOST_B)
        status, data, _ = request(flag, 'B1', 'POST', BASE,
                                  {'permission': 'leads.view', 'scope': 'SELF'},
                                  token(runtime / f'wire_{RUN}_{flag}_B1.jar'), host=HOST_B)
        check(flag, 'B1_NO_MEMBER_MANAGE', (status, data), 403)
        status, data, _ = request(flag, 'guest', 'GET', '/api/v1/company/staff')
        check(flag, 'GUEST', (status, data), 401)
        status, data, _ = request(flag, 'A5', 'POST', BASE,
                                  {'permission': 'leads.view', 'scope': 'SELF'})
        check(flag, 'CSRF_MISSING', (status, data), 419)
        status, data, _ = request(flag, 'A5', 'GET', '/api/v1/company/staff', host=HOST_B)
        check(flag, 'CROSS_HOST', (status, data), 401)
        if state_count() != revoked:
            raise RuntimeError('Wire negative changed authority')
        return {'grant': granted, 'revoke': revoked}
    finally:
        stop(processes)


for port in (18111, 18112):
    port_free(port)
evidence = {'system_identifier': state['system_identifier'], 'baseline_fingerprint': baseline, 'results': results}
try:
    evidence['OFF'] = run('OFF')
    reset()
    evidence['ON'] = run('ON')
    reset()
    processes = start('MISSING_A5', missing_a5=True)
    try:
        csrf = login('MISSING_A5', 'A5')
        status, data, _ = request('MISSING_A5', 'A5', 'POST', BASE,
                                  {'permission': 'leads.view', 'scope': 'SELF'}, csrf)
        evidence['missing_a5_status'] = status
        if status < 400 or state_count() != [0, 0, int(version), 0]:
            raise RuntimeError('Missing A5 credential accepted or mutated authority')
        print(f'MISSING_A5_FAIL_CLOSED status={status}', flush=True)
        login('MISSING_A5', 'A1')
        a1_status, _, _ = request('MISSING_A5', 'A1', 'GET', '/api/v1/company/leads')
        evidence['missing_a5_a1_leads_status'] = a1_status
        if a1_status != 200 or state_count() != [0, 0, int(version), 0]:
            raise RuntimeError('A1 independent credential or authority state failed')
        print('MISSING_A5_A1_INDEPENDENT status=200', flush=True)
    finally:
        stop(processes)
    evidence['final_fingerprint'] = b.pg_query(container, FP)
finally:
    (b.SRC / 'http_admin_evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
print('G6_HTTP_OFF_ON=PASS FINGERPRINT=STABLE')

