#!/usr/bin/env python3
"""Regression tests: a silent peer must not be able to wedge the API's threads.

Why this file exists
--------------------
On 2026-10-09 (sdbees) both :8000 API workers had 7 of 8 gthread pool threads
blocked in the kernel in tcp_recvmsg -> sk_wait_data, /health hung 40s+, and the
container stayed "healthy". The app makes no in-process outbound socket reads;
the blocked reads were gunicorn gthread reading the CLIENT socket, which it
makes fully blocking with no timeout (TConn.init -> setblocking(True)).

These tests run REAL gunicorn processes (no mocks) against tiny WSGI apps and
pin:

  * the failure mode itself, on the stock gthread worker (control);
  * that haproxy_gunicorn_worker.TimeoutThreadWorker frees the thread when a
    client stalls before / during the request line, mid-body, or on a reused
    keep-alive connection;
  * that a legitimately SLOW request (handling time > client timeout) is not
    cut off -- the timeout bounds socket I/O, not request duration;
  * the watchdog: a worker whose every thread is stuck is replaced;
  * the timeout is logged as one line, not a traceback per scanner;
  * haproxy_manager's socket.setdefaulttimeout: an in-process client call to a
    stalled upstream (accepts, never replies) times out instead of hanging;
  * why that default alone is not enough (setblocking(True) clears it).

Running
-------
    python3 scripts/test-gunicorn-socket-timeouts.py

stdlib unittest, like the other scripts/test-*.py; needs only the app's own
requirements (gunicorn, Flask...). Runs in the Docker build gate. ~25s.
"""

import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.request

REPO_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

try:
    import gunicorn  # noqa: F401
except ImportError:
    sys.stderr.write('SKIP: gunicorn not installed (pip install -r requirements.txt)\n')
    raise SystemExit(77)

WSGI_APP = textwrap.dedent('''\
    import os, time

    def app(environ, start_response):
        path = environ.get('PATH_INFO', '/')
        if path == '/sleep':
            time.sleep(float(environ.get('QUERY_STRING') or 3))
        elif path == '/hang':
            time.sleep(3600)
        elif path == '/body':
            n = int(environ.get('CONTENT_LENGTH') or 0)
            environ['wsgi.input'].read(n)
        body = ('pid=%d' % os.getpid()).encode()
        start_response('200 OK', [('Content-Type', 'text/plain'),
                                  ('Content-Length', str(len(body)))])
        return [body]
''')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http_get(port, path='/', timeout=5):
    with urllib.request.urlopen('http://127.0.0.1:%d%s' % (port, path),
                                timeout=timeout) as r:
        return r.read().decode()


class Gunicorn:
    """A real gunicorn master on a free port, with its output captured."""

    def __init__(self, worker_class, threads=1, env=None):
        self.tmp = tempfile.mkdtemp(prefix='gunicorn-timeout-test-')
        with open(os.path.join(self.tmp, 'tapp.py'), 'w') as fh:
            fh.write(WSGI_APP)
        self.port = free_port()
        self.log_path = os.path.join(self.tmp, 'gunicorn.log')
        e = dict(os.environ)
        e.update(env or {})
        self.log = open(self.log_path, 'w')
        self.proc = subprocess.Popen(
            [sys.executable, '-m', 'gunicorn',
             '--bind', '127.0.0.1:%d' % self.port,
             '--workers', '1', '--threads', str(threads),
             '--worker-class', worker_class,
             '--timeout', '120', '--graceful-timeout', '2',
             '--log-level', 'info', '--error-logfile', '-',
             '--pythonpath', '%s,%s' % (REPO_DIR, self.tmp),
             'tapp:app'],
            stdout=self.log, stderr=subprocess.STDOUT, env=e)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                http_get(self.port, '/', timeout=1)
                return
            except Exception:
                time.sleep(0.2)
        self.stop()
        raise RuntimeError('gunicorn did not come up:\n' + self.output())

    def output(self):
        self.log.flush()
        with open(self.log_path) as fh:
            return fh.read()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.close()


def stall_client(port, payload=b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03'):
    """Connect and send a few bytes that are not a complete HTTP request (by
    default the start of a TLS ClientHello -- what an HTTPS scanner sends to
    this plain-HTTP port), then go silent and keep the connection open."""
    s = socket.create_connection(('127.0.0.1', port))
    if payload:
        s.sendall(payload)
    return s


def wait_closed_by_server(sock, within):
    """True if the server closed (EOF/RST) the connection within `within` s."""
    sock.settimeout(within)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                return True
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


STOCK = 'gthread'
FIXED = 'haproxy_gunicorn_worker.TimeoutThreadWorker'
FAST = {'HAPROXY_MGR_CLIENT_TIMEOUT': '1'}


class StockGthreadControl(unittest.TestCase):
    """Proves the failure mode is real, so the fixed-worker tests mean something."""

    def test_stock_gthread_is_wedged_by_one_silent_client(self):
        g = Gunicorn(STOCK, threads=1)
        self.addCleanup(g.stop)
        s = stall_client(g.port)
        self.addCleanup(s.close)
        time.sleep(0.3)
        with self.assertRaises(Exception, msg='stock gthread should be wedged'):
            http_get(g.port, '/', timeout=3)


class TimeoutWorkerTests(unittest.TestCase):

    def start(self, threads=1, env=None):
        g = Gunicorn(FIXED, threads=threads, env=env or FAST)
        self.addCleanup(g.stop)
        return g

    def test_silent_client_is_dropped_and_thread_freed(self):
        g = self.start()
        s = stall_client(g.port)
        self.addCleanup(s.close)
        t0 = time.time()
        # Only one thread: this request can only be served once the stalled
        # connection has released it.
        self.assertTrue(http_get(g.port, '/', timeout=5).startswith('pid='))
        self.assertLess(time.time() - t0, 4)
        self.assertTrue(wait_closed_by_server(s, 3),
                        'server should have closed the stalled connection')

    def test_connect_and_send_nothing_does_not_hold_a_thread(self):
        # Never readable -> never handed to a pool thread (main loop only).
        g = self.start()
        s = stall_client(g.port, payload=b'')
        self.addCleanup(s.close)
        self.assertTrue(http_get(g.port, '/', timeout=3).startswith('pid='))

    def test_half_written_headers(self):
        g = self.start()
        s = stall_client(g.port, payload=b'GET /health HTTP/1.1\r\nHost: x\r\n')
        self.addCleanup(s.close)
        self.assertTrue(http_get(g.port, '/', timeout=5).startswith('pid='))
        self.assertTrue(wait_closed_by_server(s, 3))

    def test_body_shorter_than_content_length(self):
        g = self.start()
        s = stall_client(g.port, payload=(
            b'POST /body HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789'))
        self.addCleanup(s.close)
        self.assertTrue(http_get(g.port, '/', timeout=5).startswith('pid='))

    def test_timeout_reapplied_on_keepalive_reuse(self):
        g = self.start()
        s = socket.create_connection(('127.0.0.1', g.port))
        self.addCleanup(s.close)
        s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
        s.settimeout(3)
        self.assertIn(b'200 OK', s.recv(4096))
        # Same connection, now stall mid-request. gthread calls conn.init()
        # (setblocking(True)) again for the reused connection.
        s.sendall(b'GET / HTT')
        time.sleep(0.3)
        self.assertTrue(http_get(g.port, '/', timeout=5).startswith('pid='))
        self.assertTrue(wait_closed_by_server(s, 3))

    def test_slow_legit_request_is_not_cut_off(self):
        # Handling takes 2.5s, client timeout is 1s: must still succeed.
        g = self.start()
        self.assertTrue(http_get(g.port, '/sleep?2.5', timeout=10).startswith('pid='))

    def test_timeout_logged_as_one_line_not_traceback(self):
        g = self.start()
        s = stall_client(g.port)
        self.addCleanup(s.close)
        http_get(g.port, '/', timeout=5)
        time.sleep(0.3)
        out = g.output()
        self.assertIn('Closed client connection idle', out)
        self.assertNotIn('Traceback', out)

    def test_watchdog_replaces_fully_wedged_worker(self):
        g = self.start(env={'HAPROXY_MGR_CLIENT_TIMEOUT': '1',
                            'HAPROXY_MGR_WEDGE_SECONDS': '2',
                            'HAPROXY_MGR_WATCHDOG_INTERVAL': '0.5'})
        pid_before = http_get(g.port, '/')
        # Wedge the only thread inside the app (not a socket read).
        hung = threading.Thread(target=lambda: self._swallow(g.port), daemon=True)
        hung.start()
        time.sleep(0.5)
        deadline = time.time() + 12
        pid_after = None
        while time.time() < deadline:
            try:
                pid_after = http_get(g.port, '/', timeout=2)
                if pid_after != pid_before:
                    break
            except Exception:
                pass
            time.sleep(0.3)
        self.assertIsNotNone(pid_after)
        self.assertNotEqual(pid_before, pid_after, 'worker was not replaced')
        out = g.output()
        self.assertIn('WEDGED WORKER', out)
        self.assertIn('tapp.py', out)  # the stuck thread's stack was dumped
        self.assertIsNone(g.proc.poll(), 'master must keep running')

    def test_watchdog_leaves_partially_busy_pool_alone(self):
        # 2 threads, one hung forever: the pool still serves, so no restart.
        g = self.start(threads=2, env={'HAPROXY_MGR_CLIENT_TIMEOUT': '1',
                                       'HAPROXY_MGR_WEDGE_SECONDS': '1',
                                       'HAPROXY_MGR_WATCHDOG_INTERVAL': '0.3'})
        pid_before = http_get(g.port, '/')
        threading.Thread(target=lambda: self._swallow(g.port), daemon=True).start()
        time.sleep(3)
        self.assertEqual(pid_before, http_get(g.port, '/', timeout=3))
        self.assertNotIn('WEDGED WORKER', g.output())

    @staticmethod
    def _swallow(port):
        try:
            http_get(port, '/hang', timeout=60)
        except Exception:
            pass


class StalledUpstreamDefaultTimeout(unittest.TestCase):
    """haproxy_manager sets socket.setdefaulttimeout() at import. An in-process
    client call to an upstream that accepts and never replies must time out."""

    def test_in_process_client_to_stalled_upstream_times_out(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(5)
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]
        accepted = []
        threading.Thread(target=lambda: accepted.append(srv.accept()),
                         daemon=True).start()
        # Import the real module in a child (it changes process-global socket
        # state and opens its log files at import), then make a client call
        # with NO explicit timeout -- what a careless future handler would do.
        probe = textwrap.dedent('''\
            import logging, os, sys, tempfile, time, urllib.request
            d = tempfile.mkdtemp()
            real = logging.FileHandler
            logging.FileHandler = lambda fn, *a, **k: real(os.path.join(d, os.path.basename(fn)), *a, **k)
            os.chdir(sys.argv[1]); sys.path.insert(0, sys.argv[1])
            import haproxy_manager
            logging.FileHandler = real
            import socket
            print('default', socket.getdefaulttimeout())
            t0 = time.time()
            try:
                urllib.request.urlopen('http://127.0.0.1:%s/' % sys.argv[2]).read()
                print('result returned')
            except Exception as e:
                print('result', type(e).__name__, round(time.time() - t0, 1))
        ''')
        env = dict(os.environ, HAPROXY_MGR_SOCKET_DEFAULT_TIMEOUT='1.5')
        r = subprocess.run([sys.executable, '-c', probe, REPO_DIR, str(port)],
                           capture_output=True, text=True, timeout=30, env=env)
        if 'No module named' in r.stderr and 'flask' in r.stderr.lower():
            self.skipTest('Flask not installed')
        self.assertIn('default 1.5', r.stdout, r.stderr)
        line = [l for l in r.stdout.splitlines() if l.startswith('result')][0]
        self.assertTrue(line.startswith('result TimeoutError '), line)
        elapsed = float(line.split()[-1])
        self.assertLess(elapsed, 5)
        self.assertTrue(accepted, 'upstream never saw the connection')
        accepted[0][0].close()

    def test_default_timeout_alone_does_not_cover_gthread_client_sockets(self):
        # Documents why the custom worker exists: gthread's setblocking(True)
        # resets any timeout -- including the process default -- to None.
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(60)
        try:
            a, b = socket.socketpair()
        finally:
            socket.setdefaulttimeout(old)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        self.assertEqual(a.gettimeout(), 60)
        a.setblocking(True)
        self.assertIsNone(a.gettimeout())


if __name__ == '__main__':
    unittest.main(verbosity=2)
