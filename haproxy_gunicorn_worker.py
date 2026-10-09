"""gunicorn gthread worker that cannot be wedged by silent or slow clients.

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
sent to this plain-HTTP port, a port scanner, a half-written request) pins
that pool thread forever. :8000 was published on 0.0.0.0 by the deploy
(`-p 8000:8000`, which bypasses firewalld) and internet scanners were measured
connecting to it. 4 such connections exhaust a worker's pool.

gunicorn's --timeout does not catch this: for gthread it only checks that the
worker's MAIN thread keeps heart-beating, and the main thread keeps polling
happily while every pool thread is stuck. --max-requests does not help either:
a worker whose threads never finish a request never reaches the limit.
socket.setdefaulttimeout() does not help: setblocking(True) explicitly resets
the timeout to None, overriding any default.

Stock gthread has two more exhaustion paths on the same port (review F1/F2):

* A connection that NEVER sends a byte never becomes readable, so it is never
  handed to a thread and never gets any deadline -- but it holds one of the
  worker's ``worker_connections`` (1000) slots. At 1000 the run loop stops
  polling altogether and only waits on futures; none exist, so even the
  attacker's FINs are never seen and the worker is wedged PERMANENTLY, still
  heart-beating, with no request in flight for a watchdog to notice.
* Slowloris: one header byte every <timeout seconds never trips a per-recv
  timeout, so a socket timeout alone does not bound header-read time.

What this worker changes
------------------------
1. CLIENT_TIMEOUT (HAPROXY_MGR_CLIENT_TIMEOUT, default 20s): every client
   socket gets an explicit socket timeout at the exact point gthread makes it
   blocking (re-applied on every keep-alive reuse). Python applies it to each
   recv() call and to each WHOLE sendall() call -- gunicorn writes a response
   chunk with one sendall, so any single chunk that takes longer than this to
   transmit is cut off. Responses here are KB-sized JSON/PEMs to localhost, so
   that never happens in practice. It does NOT bound how long the app takes to
   handle a request (a long certbot run is a subprocess with its own timeout
   and touches the client socket only once it is done).

2. FIRST_BYTE_TIMEOUT (HAPROXY_MGR_FIRST_BYTE_TIMEOUT, default 10s): an
   accepted connection that has not become readable within this is closed by
   the main loop, freeing its slot (review F1).

3. HEADER_DEADLINE (HAPROXY_MGR_HEADER_DEADLINE, default 10s): total time a
   client may take to deliver the request line + headers, counted from when
   the connection was ENQUEUED for a thread, with a floor of
   HAPROXY_MGR_HEADER_PICKUP_GRACE (1s) after a thread picks it up:
   deadline = max(enqueue + 10s, pickup + 1s). Disarmed in handle_request()
   (which gunicorn calls only once the parser has returned a complete
   request). A 1s monitor loop shuts down (SHUT_RDWR, not close -- no fd-reuse
   race with the blocked recv) the socket of any connection past it; the
   blocked recv returns EOF and the thread is freed (review F2). A legit
   request queued behind busy threads (certbot runs) already has its headers
   in the kernel buffer and parses in milliseconds inside the 1s grace; a
   slow client that sat in the queue gets only the grace, so reconnecting
   drippers cannot starve the pool by queueing (re-review). Bodies are only
   read by routes behind require_api_key, so the unauthenticated surface is
   exactly this phase.

4. Wedge watchdog (HAPROXY_MGR_WEDGE_SECONDS, default 3600s; 0 disables). If
   EVERY pool thread has been inside the same request for longer than that the
   worker logs every thread's Python stack to the error log and exits; the
   gunicorn master respawns it in about a second, without touching HAProxy or
   the edge. 3600s because a multi-domain /api/certificates/request runs one
   certbot (up to 180s) per domain; with (1)-(3) closing the known client-side
   sources, this is only a backstop for blocking sources not yet found.

5. Peer filter (re-review R1). haproxy-manager shares the client-net bridge
   with every tenant container, so tenant PHP could reach haproxy-manager:8000
   directly; the 127.0.0.1 publish only removes the internet path. On the
   ports in HAPROXY_MGR_PEER_FILTER_PORTS (default "8000" -- NOT the :8080
   default-page server, which HAProxy feeds over loopback) accept() closes
   any connection whose peer is not in HAPROXY_MGR_API_ALLOWED_PEERS (default
   "127.0.0.1,::1,gateway"; IPs/CIDRs; "gateway" = this container's default
   gateway, which is where host callers arrive from through docker-proxy).
   Refused before a thread or connection slot is used; logged at most once a
   minute as a per-peer summary. Effective only once the edge publishes
   127.0.0.1:8000 -- with a 0.0.0.0 publish a tenant can hairpin through the
   host and arrive from the gateway too.

6. pool_status() exposes busy/total threads and the oldest in-flight age so
   /health can report saturation.

This overrides gthread internals (enqueue_req, accept,
on_client_socket_readable, murder_keepalived, handle, handle_request) as they
are in gunicorn 23.0.0, which requirements.txt pins. A warning is logged if a
different version is loaded; scripts/test-gunicorn-socket-timeouts.py runs
real gunicorn in the Docker build gate and fails on behavioural drift.
"""

import errno
import ipaddress
import logging
import os
import selectors
import socket
import sys
import threading
import time
import traceback
from collections import deque
from functools import partial

import gunicorn
from gunicorn.workers.gthread import TConn, ThreadWorker


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


CLIENT_TIMEOUT = _env_float('HAPROXY_MGR_CLIENT_TIMEOUT', 20)
FIRST_BYTE_TIMEOUT = _env_float('HAPROXY_MGR_FIRST_BYTE_TIMEOUT', 10)
HEADER_DEADLINE = _env_float('HAPROXY_MGR_HEADER_DEADLINE', 10)
WEDGE_SECONDS = _env_float('HAPROXY_MGR_WEDGE_SECONDS', 3600)
WATCHDOG_INTERVAL = _env_float('HAPROXY_MGR_WATCHDOG_INTERVAL', 15)
MONITOR_TICK = 1.0
# Once a thread picks a queued connection up it gets at least this long to
# finish its headers, even if its enqueue-based deadline has already passed.
HEADER_PICKUP_GRACE = _env_float('HAPROXY_MGR_HEADER_PICKUP_GRACE', 1)

# Peer filter (review R1). Listener ports it applies to (comma-separated;
# empty disables) and the peers allowed through. "gateway" means this
# container's default gateway on its bridge network -- the address host-side
# callers arrive from via the 127.0.0.1:8000 publish (docker-proxy) and via a
# direct host->container-IP connect. Tenant containers on the same bridge
# (client-net) arrive from their OWN addresses and are refused.
PEER_FILTER_PORTS = os.environ.get('HAPROXY_MGR_PEER_FILTER_PORTS', '8000')
ALLOWED_PEERS_SPEC = os.environ.get('HAPROXY_MGR_API_ALLOWED_PEERS', '127.0.0.1,::1,gateway')
PEER_REJECT_LOG_INTERVAL = 60.0


def _default_gateways(route_file='/proc/net/route'):
    """IPv4 default gateway(s) from the kernel routing table."""
    gws = []
    try:
        with open(route_file) as fh:
            next(fh, None)
            for line in fh:
                f = line.split()
                if len(f) >= 4 and f[1] == '00000000' and int(f[3], 16) & 0x2:
                    gws.append(str(ipaddress.IPv4Address(int(f[2], 16).to_bytes(4, 'little'))))
    except (OSError, ValueError):
        pass
    return gws


def parse_allowed_peers(spec, gateways=None):
    """Return (networks, problems). Tokens: IPs, CIDRs, or the word
    'gateway'. Unparseable tokens are reported, never silently widened."""
    nets, problems = [], []
    for tok in (t.strip() for t in (spec or '').split(',')):
        if not tok:
            continue
        if tok.lower() == 'gateway':
            gws = _default_gateways() if gateways is None else gateways
            if not gws:
                problems.append('gateway: no IPv4 default route found')
            for g in gws:
                nets.append(ipaddress.ip_network(g + '/32'))
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            problems.append('unparseable entry %r' % tok)
    return nets, problems


def peer_allowed(addr, nets):
    try:
        ip = ipaddress.ip_address(addr.split('%', 1)[0])
    except (ValueError, AttributeError):
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in nets)

TESTED_GUNICORN_VERSION = '23.0.0'

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


class _InFlight:
    __slots__ = ('conn', 'start', 'header_deadline')

    def __init__(self, conn, start, header_deadline):
        self.conn = conn
        self.start = start
        self.header_deadline = header_deadline


class TimeoutThreadWorker(ThreadWorker):
    """gthread worker with client-socket timeouts, a first-byte deadline, a
    total header deadline and a wedge watchdog. See module docstring."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._inflight = {}          # thread ident -> _InFlight
        self._inflight_lock = threading.Lock()
        self._pending = deque()      # accepted, not yet readable (FIFO by deadline)
        self._filter_ports = set()
        for tok in PEER_FILTER_PORTS.split(','):
            tok = tok.strip()
            if tok.isdigit():
                self._filter_ports.add(int(tok))
        self._allowed_nets = []
        self._rejected = {}          # peer ip -> count since last log line
        self._rejected_lock = threading.Lock()
        self._last_reject_log = 0.0

    # -- (1) client socket timeout ------------------------------------------
    def enqueue_req(self, conn):
        # Same three steps as ThreadWorker.enqueue_req, with the timeout set
        # right after conn.init() -- init() is what calls setblocking(True)
        # (== settimeout(None)), and it runs again on every keep-alive reuse,
        # so the timeout must be re-applied here each time, not at accept().
        conn.init()
        if CLIENT_TIMEOUT > 0:
            conn.sock.settimeout(CLIENT_TIMEOUT)
        conn.whp_enqueued = time.monotonic()   # header deadline counts from here
        fs = self.tpool.submit(self.handle, conn)
        self._wrap_future(fs, conn)

    # -- (2) first-byte deadline for never-readable connections ---------------
    def accept(self, server, listener):
        # ThreadWorker.accept (23.0.0) plus: a deadline, and the conn is
        # tracked in self._pending so murder_keepalived() can reap it.
        try:
            sock, client = listener.accept()
            if self._filter_ports and self._server_port(server) in self._filter_ports \
                    and not peer_allowed(client[0] if isinstance(client, tuple) else '',
                                         self._allowed_nets):
                # Refused before it costs a TConn, a connection slot, a poller
                # registration or a thread.
                sock.close()
                self._note_rejected(client[0] if isinstance(client, tuple) else str(client))
                return
            conn = TConn(self.cfg, sock, client, server)
            conn.timeout = time.time() + FIRST_BYTE_TIMEOUT

            self.nr_conns += 1
            with self._lock:
                self._pending.append(conn)
                self.poller.register(conn.sock, selectors.EVENT_READ,
                                     partial(self.on_client_socket_readable, conn))
        except OSError as e:
            if e.errno not in (errno.EAGAIN, errno.ECONNABORTED,
                               errno.EWOULDBLOCK):
                raise

    @staticmethod
    def _server_port(server):
        try:
            return int(server[1])
        except (TypeError, IndexError, ValueError):
            return None

    def _note_rejected(self, peer):
        with self._rejected_lock:
            self._rejected[peer] = self._rejected.get(peer, 0) + 1
        if time.monotonic() - self._last_reject_log >= PEER_REJECT_LOG_INTERVAL:
            self._flush_rejected()

    def _flush_rejected(self):
        with self._rejected_lock:
            if not self._rejected:
                return
            items, self._rejected = self._rejected, {}
            self._last_reject_log = time.monotonic()
        total = sum(items.values())
        top = sorted(items.items(), key=lambda kv: -kv[1])[:5]
        self.log.warning(
            'Refused %d connection(s) to the management API from %d non-allowed peer(s) '
            '(HAPROXY_MGR_API_ALLOWED_PEERS=%s): %s%s', total, len(items), ALLOWED_PEERS_SPEC,
            ', '.join('%s x%d' % kv for kv in top), ' ...' if len(items) > 5 else '')

    def on_client_socket_readable(self, conn, client):
        # ThreadWorker version only knows about self._keep; a first request
        # comes off self._pending instead.
        with self._lock:
            self.poller.unregister(client)
            queue = self._keep if conn.initialized else self._pending
            try:
                queue.remove(conn)
            except ValueError:
                # already reaped (race with murder_keepalived)
                return
        self.enqueue_req(conn)

    def murder_keepalived(self):
        # Runs on every pass of ThreadWorker.run() -- including the branch
        # taken when nr_conns >= worker_connections, where the poller is not
        # serviced. Reaping here is what breaks that permanent deadlock.
        super().murder_keepalived()
        if FIRST_BYTE_TIMEOUT <= 0:
            return
        now = time.time()
        while True:
            with self._lock:
                if not self._pending or self._pending[0].timeout > now:
                    break
                conn = self._pending.popleft()
                try:
                    self.poller.unregister(conn.sock)
                except (OSError, KeyError, ValueError):
                    pass
            self.nr_conns -= 1
            conn.close()

    # -- (3) header deadline + busy tracking ----------------------------------
    def handle(self, conn):
        ident = threading.get_ident()
        now = time.monotonic()
        deadline = None
        if HEADER_DEADLINE > 0:
            # max(enqueue + D, pickup + grace): a legit request that waited in
            # the queue behind busy threads already has its headers in the
            # kernel buffer and parses in milliseconds; a slow client that
            # waited gets only the grace, not a fresh full deadline (review:
            # 40 reconnecting drippers otherwise starved legit requests).
            enq = getattr(conn, 'whp_enqueued', now)
            deadline = max(enq + HEADER_DEADLINE, now + HEADER_PICKUP_GRACE)
        entry = _InFlight(conn, now, deadline)
        with self._inflight_lock:
            self._inflight[ident] = entry
        try:
            return super().handle(conn)
        finally:
            with self._inflight_lock:
                self._inflight.pop(ident, None)

    def handle_request(self, req, conn):
        # The parser has produced a complete request line + headers.
        entry = self._inflight.get(threading.get_ident())
        if entry is not None:
            entry.header_deadline = None
        return super().handle_request(req, conn)

    def _sweep_header_deadlines(self):
        now = time.monotonic()
        with self._inflight_lock:
            late = [e for e in self._inflight.values()
                    if e.header_deadline is not None and e.header_deadline < now]
        for e in late:
            e.header_deadline = None   # one shutdown per connection
            try:
                # shutdown, not close: wakes the blocked recv() with EOF
                # without releasing the fd while another thread is in it.
                e.conn.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if late:
            self.log.info('Cut %d client connection(s) still sending request headers '
                          'after %ss (HAPROXY_MGR_HEADER_DEADLINE)', len(late), HEADER_DEADLINE)

    def pool_status(self):
        now = time.monotonic()
        with self._inflight_lock:
            starts = [e.start for e in self._inflight.values()]
        return {
            'pid': os.getpid(),
            'threads': self.cfg.threads,
            'busy': len(starts),
            'oldest_busy_seconds': round(now - min(starts), 1) if starts else 0.0,
            'client_timeout_seconds': CLIENT_TIMEOUT,
        }

    # -- (4) watchdog ---------------------------------------------------------
    def _wedged_for(self):
        """Seconds the pool has been completely wedged (every thread busy in
        its current request), measured from the YOUNGEST in-flight request.
        0 when at least one thread is free."""
        with self._inflight_lock:
            starts = [e.start for e in self._inflight.values()]
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

    def _check_wedged(self):
        wedged = self._wedged_for()
        if WEDGE_SECONDS > 0 and wedged > WEDGE_SECONDS:
            try:
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
            finally:
                # os._exit, not SIGTERM: a graceful exit joins the (stuck,
                # non-daemon) pool threads at interpreter shutdown and would
                # hang until the master's --timeout escalates to SIGKILL.
                os._exit(WEDGED_EXIT_CODE)

    def _monitor(self):
        """One daemon thread: header-deadline sweep every second, wedge check
        every WATCHDOG_INTERVAL. Never allowed to die silently."""
        last_wedge_check = time.monotonic()
        while self.alive:
            time.sleep(MONITOR_TICK)
            try:
                if HEADER_DEADLINE > 0:
                    self._sweep_header_deadlines()
                if time.monotonic() - self._last_reject_log >= PEER_REJECT_LOG_INTERVAL:
                    self._flush_rejected()
                if time.monotonic() - last_wedge_check >= WATCHDOG_INTERVAL:
                    last_wedge_check = time.monotonic()
                    self._check_wedged()
            except Exception:
                try:
                    self.log.exception('haproxy_gunicorn_worker monitor error (continuing)')
                except Exception:
                    pass

    def init_process(self):
        global _current_worker
        _current_worker = self
        try:
            self.log.error_log.addFilter(_QuietClientTimeout())
        except AttributeError:
            pass
        if gunicorn.__version__ != TESTED_GUNICORN_VERSION:
            self.log.warning(
                'haproxy_gunicorn_worker overrides gthread internals as of gunicorn %s; '
                'running %s -- re-run scripts/test-gunicorn-socket-timeouts.py',
                TESTED_GUNICORN_VERSION, gunicorn.__version__)
        if self._filter_ports:
            self._allowed_nets, problems = parse_allowed_peers(ALLOWED_PEERS_SPEC)
            for prob in problems:
                self.log.error('HAPROXY_MGR_API_ALLOWED_PEERS: %s -- that entry allows nothing '
                               '(fail closed)', prob)
            self.log.info('Management API peer filter on port(s) %s: allowing %s',
                          ','.join(str(p) for p in sorted(self._filter_ports)),
                          ', '.join(str(n) for n in self._allowed_nets) or 'NOTHING')
        threading.Thread(target=self._monitor, name='worker-monitor',
                         daemon=True).start()
        super().init_process()   # runs the event loop; does not return
