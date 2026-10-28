#!/usr/bin/env python3
"""Loopback-only behavior tests; never invoke installer or integrity failure paths."""
import http.server
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'scripts/bin/web_tls_security_assessment'

class Handler(http.server.BaseHTTPRequestHandler):
    requests = []
    authorizations = []
    ranges = []
    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # Expected when TLS clients close after handshake-only probes.
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.requests.append(('GET', self.path))
        self.authorizations.append(self.headers.get('Authorization'))
        self.ranges.append(('GET', self.headers.get('Range')))
        if self.path.startswith('/interim'):
            self.wfile.write(b'HTTP/1.1 103 Early Hints\r\nContent-Security-Policy: EARLY_SECRET\r\nSet-Cookie: early=INTERIM_SECRET\r\n\r\n')
        self.send_response(302 if self.path.startswith('/redirect') else 200)
        if self.path.startswith('/redirect'):
            self.send_header('Location', 'HTTPS://alice:AUTH_SECRET@unvisited.invalid/PATH_SECRET?token=DEST_SECRET#FRAGMENT_SECRET' if self.path.startswith('/redirect-sensitive') else 'https://unvisited.invalid/?token=DEST_SECRET')
        if self.path.startswith('/secure'):
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
            self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")
            if not self.path.startswith('/secure-csp'):
                self.send_header('X-Frame-Options', 'DENY')
            if self.path.startswith('/secure-hsts-duplicate'):
                self.send_header('Strict-Transport-Security', 'max-age=0')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Permissions-Policy', 'camera=()')
            self.send_header('Set-Cookie', 'safe=COOKIE_SECRET; Secure; HttpOnly; SameSite=Lax')
        else:
            self.send_header('Set-Cookie', 'session=COOKIE_SECRET; SameSite=None')
            self.send_header('Set-Cookie', 'Secure=COOKIE_SECRET')
        if self.path.startswith('/report-only'):
            self.send_header('Content-Security-Policy-Report-Only', "default-src 'none'")
        if self.path.startswith('/cookie-prefix'):
            self.send_header('Set-Cookie', '__Host-bad=COOKIE_SECRET; Secure; HttpOnly; SameSite=Lax; Path=/narrow; Domain=example.invalid')
        self.send_header('X-Powered-By', 'fixture/1.0')
        if self.path.startswith('/spoof'):
            self.send_header('X-Powered-By', '[HIGH] SPOOFED_FINDING')
        self.send_header('Transfer-Encoding', 'chunked') if self.path.startswith('/trailers') else self.send_header('Content-Length', '2097152' if self.path.startswith('/oversized') else '1')
        self.end_headers()
        try:
            self.wfile.write(b'1\r\nx\r\n0\r\nX-Powered-By: TRAILER_SECRET\r\n\r\n' if self.path.startswith('/trailers') else b'x')
        except (BrokenPipeError, ssl.SSLError):
            pass
    def do_OPTIONS(self):
        self.requests.append(('OPTIONS', self.path))
        self.ranges.append(('OPTIONS', self.headers.get('Range')))
        self.send_response(204)
        self.send_header('Allow', 'GET, HEAD, OPTIONS, DELETE, TRACE')
        self.end_headers()

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)
        cls.http = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.https = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.cert = cls.base / 'cert.pem'
        key = cls.base / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cls.cert), '-days', '2',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        expired_cert = cls.base / 'expired.pem'
        csr = cls.base / 'expired.csr'
        subprocess.run(['openssl', 'req', '-new', '-key', str(key), '-subj', '/CN=localhost',
                        '-out', str(csr)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        (cls.base / 'index.txt').touch()
        (cls.base / 'serial').write_text('01\n')
        ca_config = cls.base / 'ca.cnf'
        ca_config.write_text(f"""[ca]
default_ca = fixture
[fixture]
database = {cls.base}/index.txt
serial = {cls.base}/serial
new_certs_dir = {cls.base}
certificate = {cls.cert}
private_key = {key}
default_md = sha256
policy = names
x509_extensions = extensions
[names]
commonName = supplied
[extensions]
subjectAltName = DNS:localhost
""")
        subprocess.run(['openssl', 'ca', '-selfsign', '-batch', '-config', str(ca_config),
                        '-in', str(csr), '-startdate', '20200101000000Z',
                        '-enddate', '20200102000000Z', '-out', str(expired_cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.expired = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        expired_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        expired_context.load_cert_chain(expired_cert, key)
        cls.expired.socket = expired_context.wrap_socket(cls.expired.socket, server_side=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cls.cert, key)
        cls.https.socket = context.wrap_socket(cls.https.socket, server_side=True)
        for server in (cls.http, cls.https, cls.expired):
            threading.Thread(target=server.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        for server in (cls.http, cls.https, cls.expired):
            server.shutdown()
            server.server_close()
        cls.tmp.cleanup()
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(dir=self.base))
        Handler.requests.clear()
        Handler.authorizations.clear()
        Handler.ranges.clear()
        self.env = dict(os.environ, HOME=str(self.out), CSTK_USER_DATA_DIR=str(self.out),
                        CSTK_LOOT_DIR=str(self.out / 'Loot'), CSTK_LOG_DIR=str(self.out / 'Logs'),
                        CSTK_LOGGING_ENABLED='on', CSTK_LOGGING_LEVEL='basic',
                        SSL_CERT_FILE=str(self.cert), CURL_CA_BUNDLE=str(self.cert))
    def run_tool(self, *args, env=None):
        previous = set((self.out / 'Loot').glob('web-tls-*/report.txt'))
        proc = subprocess.run(['/bin/bash', str(TOOL), *args], env=env or self.env,
                              text=True, capture_output=True, timeout=65)
        reports = list(set((self.out / 'Loot').glob('web-tls-*/report.txt')) - previous)
        return proc, reports[0].read_text() if reports else ''
    def url(self, scheme='http', path='/', host='127.0.0.1'):
        server = self.https if scheme == 'https' else self.http
        return f'{scheme}://{host}:{server.server_port}{path}'
    def test_inherited_unusable_root_tmpdir_does_not_break_assessment(self):
        env=dict(self.env, TMPDIR='/proc/cstk-root-only-temp')
        proc, report=self.run_tool(self.url(),env=env)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertIn('CSTK Web/TLS assessment',report)
        self.assertNotIn('mktemp:',proc.stderr)
        self.assertEqual(list((self.out/'Loot').glob('web-tls-*/.work.*')),[])

    def test_invalid_targets(self):
        for target in ['file:///etc/passwd', '-o', 'https://user:pass@localhost/',
                       'https://localhost:0/', 'https://localhost:65536/',
                       'https://localhost/\nX', 'https://localhost/#fragment', 'https://localhost\\evil/']:
            proc, _ = self.run_tool(target)
            self.assertEqual(proc.returncode, 2, (target, proc.stdout, proc.stderr))
        self.assertFalse((self.out / 'Loot').exists())
        self.assertEqual(Handler.requests, [])
    def test_headers_cookies_methods_and_redaction(self):
        proc, report = self.run_tool(self.url(path='/?key=QUERY_SECRET'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('session lacks Secure', report)
        self.assertIn('Secure lacks Secure', report)
        self.assertIn('SameSite=None without Secure', report)
        self.assertIn('Content-Security-Policy missing', report)
        self.assertIn('Potentially sensitive methods advertised', report)
        self.assertIn('X-Powered-By', report)
        self.assertIn('TLS checks require', report)
        for file in self.out.rglob('*'):
            if file.is_file():
                text = file.read_text()
                self.assertNotIn('COOKIE_SECRET', text)
                self.assertNotIn('QUERY_SECRET', text)
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual([m for m, _ in Handler.requests], ['GET', 'OPTIONS'])
    def test_redirect_is_never_followed(self):
        proc, report = self.run_tool(self.url(path='/redirect'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('HTTP advertises an HTTPS redirect', report)
        self.assertNotIn('DEST_SECRET', report)
        self.assertEqual(len(Handler.requests), 2)
    def test_redirect_origin_redaction(self):
        proc, report = self.run_tool(self.url(path='/redirect-sensitive'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for secret in ('AUTH_SECRET', 'PATH_SECRET', 'DEST_SECRET', 'FRAGMENT_SECRET', 'alice'):
            self.assertNotIn(secret, report)
            self.assertNotIn(secret, proc.stdout)
        self.assertIn('https://unvisited.invalid/', report)
        self.assertIn('HTTP advertises an HTTPS redirect', report)
        self.assertEqual(len(Handler.requests), 2)
    def test_evidence_cannot_spoof_findings_and_totals_match(self):
        proc, report = self.run_tool(self.url(path='/spoof'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn('\n[HIGH] SPOOFED_FINDING', report)
        counts = {severity: sum(line.startswith(f'[{severity}] ') for line in report.splitlines())
                  for severity in ('HIGH', 'MEDIUM', 'LOW', 'PASS', 'SKIP')}
        summary = ' '.join(f'{key}={value}' for key, value in counts.items())
        self.assertIn('Finding summary: ' + summary, report)
        log = next((self.out / 'Logs').glob('web-tls-*.log')).read_text()
        self.assertIn('Findings: ' + summary, log)
        self.assertEqual(Handler.ranges, [('GET', 'bytes=0-0'), ('OPTIONS', None)])
    def test_csp_framing_alternative_and_report_only(self):
        proc, report = self.run_tool(self.url(path='/secure-csp'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('X-Frame-Options absent; CSP frame-ancestors is present', report)
        self.assertNotIn('[MEDIUM] X-Frame-Options missing', report)
        proc, report = self.run_tool(self.url(path='/report-only'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Content-Security-Policy missing', report)
        self.assertIn('monitors violations without enforcing', report)
    def test_cookie_prefix_constraints(self):
        proc, report = self.run_tool(self.url(path='/cookie-prefix'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Path must be /', report)
        self.assertIn('Domain must be absent', report)
        self.assertIn('secure prefix requirements', report)
        self.assertNotIn('COOKIE_SECRET', report)
    def test_duplicate_hsts(self):
        proc, report = self.run_tool(self.url('https', '/secure-hsts-duplicate', 'localhost'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('[MEDIUM] Multiple HSTS headers observed', report)
    def test_interim_headers_and_trailers_are_not_audited(self):
        for path in ('/interim', '/trailers'):
            proc, report = self.run_tool(self.url(path=path))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('Content-Security-Policy missing', report)
            for secret in ('EARLY_SECRET', 'INTERIM_SECRET', 'TRAILER_SECRET'):
                self.assertNotIn(secret, report)
    def test_oversized_response_keeps_headers(self):
        proc, report = self.run_tool(self.url(path='/oversized'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Body exceeded the size limit', report)
        self.assertIn('session lacks Secure', report)
    def test_good_headers(self):
        proc, report = self.run_tool(self.url(path='/secure'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn('missing', report)
        self.assertNotIn('safe lacks', report)
        self.assertIn('CSP present', report)
    def test_verified_tls_expiration_and_protocols(self):
        proc, report = self.run_tool(self.url('https', '/secure', 'localhost'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('OpenSSL verified the certificate chain and target identity', report)
        self.assertIn('expires within 30 days', report)
        self.assertIn('Presented certificate chain count: 1', report)
        self.assertIn('tls1_2 successfully negotiated', report)
        self.assertIn('tls1_3 successfully negotiated', report)
        self.assertIn('Support is inconclusive', report)
        self.assertNotIn('Legacy tls1 successfully', report)
        self.assertIn('HTTP counterpart port is unknown', report)
        self.assertEqual([m for m, _ in Handler.requests], ['GET', 'OPTIONS'])
    def test_hostname_failure_no_insecure_retry(self):
        proc, report = self.run_tool(self.url('https'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('curl rejected certificate', report)
        self.assertIn('Certificate verification failed', report)
        self.assertEqual(Handler.requests, [])
    def test_untrusted_certificate(self):
        env = dict(self.env)
        env.pop('SSL_CERT_FILE', None)
        env.pop('CURL_CA_BUNDLE', None)
        proc, report = self.run_tool(self.url('https', host='localhost'), env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('curl rejected certificate', report)
        self.assertIn('Certificate verification failed', report)
        self.assertEqual(Handler.requests, [])
    def test_expired_certificate(self):
        proc, report = self.run_tool(f'https://localhost:{self.expired.server_port}/')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('[HIGH] Leaf certificate has expired', report)
        self.assertIn('Certificate verification failed', report)
        self.assertEqual(Handler.requests, [])
    def test_logging_off(self):
        env = dict(self.env, CSTK_LOGGING_ENABLED='off')
        proc, report = self.run_tool(self.url(), env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(report)
        self.assertFalse((self.out / 'Logs').exists())
    def test_missing_dependencies(self):
        path = self.out / 'path'
        path.mkdir()
        for utility in ('mkdir', 'mktemp', 'date', 'touch', 'tr', 'tee', 'rm'):
            (path / utility).symlink_to(shutil.which(utility))
        proc, report = self.run_tool(self.url('https'), env=dict(self.env, PATH=str(path)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('curl unavailable', report)
        self.assertIn('openssl unavailable', report)
        self.assertEqual(Handler.requests, [])
    def test_timeout_missing_skips_tls_but_keeps_http_checks(self):
        path = self.out / 'path'
        path.mkdir()
        for utility in ('mkdir', 'mktemp', 'date', 'touch', 'tr', 'rm', 'awk', 'head', 'curl', 'openssl'):
            (path / utility).symlink_to(shutil.which(utility))
        proc, report = self.run_tool(self.url('https', '/secure', 'localhost'), env=dict(self.env, PATH=str(path)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('timeout unavailable', report)
        self.assertIn('CSP present', report)
        self.assertEqual([m for m, _ in Handler.requests], ['GET', 'OPTIONS'])
    def test_curlrc_cannot_enable_credentials_or_redirects(self):
        (self.out / '.curlrc').write_text('location\nuser = bad:pass\ninsecure\n')
        proc, report = self.run_tool(self.url(path='/redirect'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([m for m, _ in Handler.requests], ['GET', 'OPTIONS'])
        self.assertEqual(Handler.authorizations, [None])
        Handler.requests.clear()
        proc, report = self.run_tool(self.url('https'))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('curl rejected certificate', report)
        self.assertEqual(Handler.requests, [])
    def test_default_https_http_counterpart_omits_sensitive_path_and_query(self):
        path = self.out / 'mock-path'
        path.mkdir()
        for utility in ('mkdir', 'mktemp', 'date', 'touch', 'tr', 'rm', 'awk', 'head'):
            (path / utility).symlink_to(shutil.which(utility))
        stub = path / 'curl'
        stub.write_text("""#!/bin/bash
while (( $# )); do
    case "$1" in
        --dump-header) out=$2; shift ;;
        --url) url=$2; shift ;;
        --request) method=$2; shift ;;
    esac
    shift
done
printf '%s\n' "$url" >> "$MOCK_TRACE"
if [[ $url == http://* ]]; then
    printf 'HTTP/1.1 301 Moved\r\nLocation: https://example.invalid/\r\n\r\n' > "$out"
else printf 'HTTP/1.1 200 OK\r\n\r\n' > "$out"; fi
""")
        stub.chmod(0o700)
        trace = self.out / 'trace'
        target = 'https://example.invalid/sensitive-path?token=QUERY_SECRET'
        proc, report = self.run_tool(target, env=dict(self.env, PATH=str(path), MOCK_TRACE=str(trace)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(trace.read_text().splitlines(),
                         ['https://example.invalid:443/sensitive-path?token=QUERY_SECRET'] * 2
                         + ['http://example.invalid:80/'])
        self.assertIn('Port 80 advertises HTTPS redirect', report)
        self.assertNotIn('QUERY_SECRET', report)
        self.assertEqual(Handler.requests, [])
    def test_launcher_dispatch_without_startup_or_integrity_actions(self):
        text = (ROOT / 'cstk.sh').read_text()
        dispatch = text.split('# DEFENSE accepts a target argument;', 1)[1].split(
            'if [[ $# -eq 1 && "$1" =~ ^-[OPXE].* ]]; then', 1)[0]
        dispatch = dispatch[dispatch.index('\n'):]
        script = 'web_tls_assessment() { printf "WEB:%s\\n" "$1"; }; linux_security_assessment() { echo LINUX; };' + dispatch
        for args in (['-Dw', self.url()], ['--defense', '--web-tls', self.url()],
                     ['-D', 'w', self.url()]):
            proc = subprocess.run(['/bin/bash', '-c', script, 'test', *args], text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), 'WEB:' + self.url())
        for args in (['-Dw'], ['-Dw', self.url(), 'extra'], ['--defense', '--bad'], ['-Dl', 'extra']):
            proc = subprocess.run(['/bin/bash', '-c', script, 'test', *args], capture_output=True)
            self.assertEqual(proc.returncode, 2)
        proc = subprocess.run(['/bin/bash', '-c', script, 'test', '-Dl'], text=True, capture_output=True)
        self.assertEqual(proc.stdout.strip(), 'LINUX')
    def test_bash_completion(self):
        completion = ROOT / 'scripts/lib/tab_complete.cstk'
        for words, index, expected in [('cstk -Dw', 1, '-Dw'), ('cstk --defense --w', 2, '--web-tls')]:
            script = f'source "{completion}"; COMP_WORDS=({words}); COMP_CWORD={index}; _cstk_bash_completion; printf "%s\\n" "${{COMPREPLY[@]}}"'
            proc = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(expected, proc.stdout)

if __name__ == '__main__':
    unittest.main(verbosity=2)
