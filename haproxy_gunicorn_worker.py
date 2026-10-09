"""gunicorn gthread worker that cannot be wedged by a silent client.

Incident 2026-10-09 (sdbees), and very likely the 2026-07-07 whp01 one too
-------------------------------------------------------------------------
Both :8000 API workers had 7 of 8 pool threads parked in the kernel in
``tcp_recvmsg -> sk_wait_data``: a blocking socket read with no timeout.
/health and /api/blocked-ips hung for 40s+, the container stayed "healthy".

haproxy_manager.py makes NO in-process outbound network reads (no requests,
urllib, http.client, raw socket or ssl client anywhere; every ACME/HAProxy
interaction is a subprocess, already bounded since 2026.07.3). The reads that
blocked were gunicorn's own reads of the CLIENT socket:

    gunicorn/workers/gthread.py  TConn.init():  self.sock.setblocking(True)

Once the main loop sees a connection become readable it hands it to a pool
thread and turns the socket fully blocking -- timeout None -- before parsing
the request. Any peer that sends a few bytes and then waits (a TLS ClientHello
sent to this plain-HTTP port, a port scanner, a half-written request, a body
shorter than its Content-Length) pins that pool thread forever. :8000 is
published on 0.0.0.0 by the deploy (`-p 8000:8000`, which bypasses firewalld),
and on sdbees internet scanners were measured connecting to it. Each such
connection leaks one thread; 4 per worker exhausts the pool.

gunicorn's --timeout does not catch this: for gthread it only checks that the
worker's MAIN thread keeps heart-beating, and the main thread keeps polling
happily while every pool thread is stuck. --max-requests does not help either:
a worker whose threads never finish a request never reaches the limit.
socket.setdefaulttimeout() does not help: setblocking(True) explicitly resets
the timeout to None, overriding any default.

What this worker changes (and nothing else)
-------------------------------------------
1. Every client connection gets an explicit socket timeout
   (HAPROXY_MGR_CLIENT_TIMEOUT, default 20s) at the exact point gthread makes it
   blocking. It bounds each recv/send on the client socket -- request line,
   headers, the body the app reads, and response writes. It does NOT bound how
   long the app takes to handle a request (a long certbot run is a subprocess
   with its own timeout and touches the client socket only once it is done).
   A stalled peer now costs one thread for at most that long, then the
   connection is closed and the thread is returned to the pool.

2. A per-worker watchdog thread (HAPROXY_MGR_WEDGE_SECONDS, default 1200s; 0
   disables). If EVERY pool thread has been inside the same request for longer
   than that -- i.e. the pool has not turned over at all for 20 minutes, longer
   than the slowest legitimate request (certbot renew, 900s) -- the worker logs
   every thread's Python stack to the error log and exits. The gunicorn master
   respawns it in about a second, without touching HAProxy or the edge.
   This is a backstop for blocking sources we have not found yet; the fix for
   the known one is (1).

3. pool_status() exposes busy/total threads and the oldest in-flight age so
   /health can report saturation.
"""

import errno
import logging
import os
import sys
import threading
import time
import traceback

from gunicorn.workers.gthread import ThreadWorker


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


CLIENT_TIMEOUT = _env_float('HAPROXY_MGR_CLIENT_TIMEOUT', 20)
WEDGE_SECONDS = _env_float('HAPROXY_MGR_WEDGE_SECONDS', 1200)
WATCHDOG_INTERVAL = _env_float('HAPROXY_MGR_WATCHDOG_INTERVAL', 15)

# Exit status for a watchdog-killed worker. Must NOT be 3 (WORKER_BOOT_ERROR)
# or 4 (APP_LOAD_ERROR): on those the gunicorn master halts the whole server
# instead of respawning the worker.
WEDGED_EXIT_CODE = 1

_current_worker = None


def pool_status():
    """Busy/total threads of the worker serving the caller, or None when the
    app is not running under this worker class (e.g. tests, dev server)."""
    w = _current_worker
    if w is None:
        return None
    return w.pool_status()


class _QuietClientTimeout(logging.Filter):
    """gthread logs any OSError without an errno it recognises as
    log.exception("Socket error processing request.") -- a full traceback.
    A client timeout is now an expected, bounded event (scanners hit this port
    constantly), so reduce it to one line instead of flooding the error log."""

    def filter(self, record):
        exc = record.exc_info[1] if record.exc_info else None
        if isinstance(exc, TimeoutError) and \
                str(record.msg).startswith('Socket error processing request'):
            record.msg = ('Closed client connection idle for more than %ss '
                          '(HAPROXY_MGR_CLIENT_TIMEOUT)' % CLIENT_TIMEOUT)
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.levelno = logging.INFO
            record.levelname = 'INFO'
        return True


class TimeoutThreadWorker(ThreadWorker):
    """gthread worker whose client sockets always carry a read/write timeout."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._inflight = {}          # thread ident -> monotonic start time
        self._inflight_lock = threading.Lock()

    # -- (1) client socket timeout ------------------------------------------
    def enqueue_req(self, conn):
        # Same three steps as ThreadWorker.enqueue_req, with the timeout set
        # right after conn.init() -- init() is what calls setblocking(True)
        # (== settimeout(None)), and it runs again on every keep-alive reuse,
        # so the timeout must be re-applied here each time, not at accept().
        conn.init()
        if CLIENT_TIMEOUT > 0:
            conn.sock.settimeout(CLIENT_TIMEOUT)
        fs = self.tpool.submit(self.handle, conn)
        self._wrap_future(fs, conn)

    # -- busy tracking --------------------------------------------------------
    def handle(self, conn):
        ident = threading.get_ident()
        with self._inflight_lock:
            self._inflight[ident] = time.monotonic()
        try:
            return super().handle(conn)
        finally:
            with self._inflight_lock:
                self._inflight.pop(ident, None)

    def pool_status(self):
        now = time.monotonic()
        with self._inflight_lock:
            starts = list(self._inflight.values())
        return {
            'pid': os.getpid(),
            'threads': self.cfg.threads,
            'busy': len(starts),
            'oldest_busy_seconds': round(now - min(starts), 1) if starts else 0.0,
            'client_timeout_seconds': CLIENT_TIMEOUT,
        }

    # -- (2) watchdog ---------------------------------------------------------
    def _wedged_for(self):
        """Seconds the pool has been completely wedged (every thread busy in
        its current request), measured from the YOUNGEST in-flight request.
        0 when at least one thread is free."""
        with self._inflight_lock:
            starts = list(self._inflight.values())
        if len(starts) < self.cfg.threads:
            return 0.0
        return time.monotonic() - max(starts)

    def _dump_stacks(self):
        frames = sys._current_frames()
        names = {t.ident: t.name for t in threading.enumerate()}
        out = []
        for ident, frame in frames.items():
            out.append('--- thread %s (%s)\n%s' % (
                ident, names.get(ident, '?'), ''.join(traceback.format_stack(frame))))
        return '\n'.join(out)

    def _watchdog(self):
        while self.alive:
            time.sleep(WATCHDOG_INTERVAL)
            wedged = self._wedged_for()
            if wedged > WEDGE_SECONDS:
                self.log.critical(
                    'WEDGED WORKER (pid %s): all %s threads busy in the same request '
                    'for %.0fs > HAPROXY_MGR_WEDGE_SECONDS=%s. Exiting so the master '
                    'respawns it. Thread stacks:\n%s',
                    os.getpid(), self.cfg.threads, wedged, WEDGE_SECONDS,
                    self._dump_stacks())
                for h in logging.getLogger('gunicorn.error').handlers:
                    try:
                        h.flush()
                    except Exception:
                        pass
                # os._exit, not SIGTERM: a graceful exit joins the (stuck,
                # non-daemon) pool threads at interpreter shutdown and would
                # hang until the master's --timeout escalates to SIGKILL.
                os._exit(WEDGED_EXIT_CODE)

    def init_process(self):
        global _current_worker
        _current_worker = self
        try:
            self.log.error_log.addFilter(_QuietClientTimeout())
        except AttributeError:
            pass
        if WEDGE_SECONDS > 0:
            threading.Thread(target=self._watchdog, name='wedge-watchdog',
                             daemon=True).start()
        super().init_process()   # runs the event loop; does not return
