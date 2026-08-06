#!/usr/bin/env python3
"""Regression tests for HAProxy config backup / rollback ordering.

Why this file exists
--------------------
generate_config() used to write the new haproxy.cfg and only THEN call
reload_haproxy_safely() -> create_backup(), so the "backup" was a copy of the
config that had just been written. On a validation failure restore_backup()
restored the identical broken bytes: the advertised rollback was a no-op and a
fatal haproxy.cfg stayed on disk, where start_haproxy() refuses to launch.

These tests pin the ordering invariant (backup predates the write) and the
observable end-to-end behaviour (after a failed validation the file on disk is
the previous working config and HAProxy will start with it).

Running
-------
    python3 scripts/test-config-rollback.py           # tests the repo checkout
    HAPROXY_MANAGER_DIR=/some/other/tree \
        python3 scripts/test-config-rollback.py       # tests another tree

The repo has no Python test framework (scripts/test-*.sh are curl-based
integration scripts against a running API), so this is a self-contained
stdlib-unittest script - no pytest, no venv, no new dependencies beyond the
application's own requirements.txt (Flask/Jinja2/psutil), which are already
present in the container image.

No HAProxy binary is required: a stub `haproxy` is put on PATH that mimics
`haproxy -c -f <file>` by rejecting any config containing the token
__BROKEN__, which is how the tests inject an invalid configuration.
"""

import os
import re
import sys
import shutil
import inspect
import sqlite3
import logging
import tempfile
import textwrap
import unittest

BROKEN_TOKEN = '__BROKEN__'

MODULE_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
)

# haproxy_manager builds its Jinja2 environment from the relative path
# Path('templates'), so it has to be imported with the module dir as cwd.
os.chdir(MODULE_DIR)
sys.path.insert(0, MODULE_DIR)

# The module opens /var/log/haproxy-manager.log at import time via
# logging.FileHandler. Redirect that one call so the suite runs unprivileged.
_LOG_DIR = tempfile.mkdtemp(prefix='haproxy-mgr-test-logs-')
_real_file_handler = logging.FileHandler
logging.FileHandler = (
    lambda fn, *a, **kw: _real_file_handler(
        os.path.join(_LOG_DIR, os.path.basename(fn)), *a, **kw)
)
try:
    import haproxy_manager as hm
except ImportError as exc:  # pragma: no cover - environment problem, not a failure
    sys.stderr.write(
        f"SKIP: cannot import haproxy_manager ({exc}).\n"
        "Install the application requirements first: pip install -r requirements.txt\n"
    )
    raise SystemExit(77)
finally:
    logging.FileHandler = _real_file_handler

logging.getLogger('haproxy_manager').setLevel(logging.CRITICAL)

FAKE_HAPROXY = textwrap.dedent(f"""\
    #!/bin/sh
    # Test stub for the haproxy binary.
    #   haproxy -c -f FILE   -> exit 1 if FILE contains {BROKEN_TOKEN}, else 0
    #   haproxy -W -S ... -f FILE (start) -> same validation, then exit 0
    cfg=""
    while [ $# -gt 0 ]; do
      case "$1" in -f) cfg="$2"; shift ;; esac
      shift
    done
    if [ -n "$cfg" ] && grep -q '{BROKEN_TOKEN}' "$cfg" 2>/dev/null; then
      echo "[ALERT] parsing [$cfg:1] : unknown keyword '{BROKEN_TOKEN}'" >&2
      exit 1
    fi
    exit 0
""")


class RollbackTestCase(unittest.TestCase):
    """Base fixture: an isolated fake /etc/haproxy plus a stub haproxy binary."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='haproxy-rollback-test-')
        self.addCleanup(shutil.rmtree, self.tmp, True)

        bindir = os.path.join(self.tmp, 'bin')
        os.makedirs(bindir)
        stub = os.path.join(bindir, 'haproxy')
        with open(stub, 'w') as fh:
            fh.write(FAKE_HAPROXY)
        os.chmod(stub, 0o755)
        self._old_path = os.environ['PATH']
        os.environ['PATH'] = bindir + os.pathsep + self._old_path
        self.addCleanup(lambda: os.environ.__setitem__('PATH', self._old_path))

        self.etc = os.path.join(self.tmp, 'etc')
        os.makedirs(self.etc)

        overrides = {
            'DB_FILE': os.path.join(self.etc, 'haproxy_config.db'),
            'HAPROXY_CONFIG_PATH': os.path.join(self.etc, 'haproxy.cfg'),
            'HAPROXY_BACKUP_PATH': os.path.join(self.etc, 'haproxy.cfg.backup'),
            'BLOCKED_IPS_MAP_PATH': os.path.join(self.etc, 'blocked_ips.map'),
            'BLOCKED_IPS_MAP_BACKUP_PATH': os.path.join(self.etc, 'blocked_ips.map.backup'),
            'CLUSTER_SECRET_PATH': os.path.join(self.etc, 'cluster-secret'),
            'SSL_CERTS_DIR': os.path.join(self.etc, 'certs'),
            'HAPROXY_SOCKET_PATH': os.path.join(self.etc, 'haproxy.sock'),
            # Added by the rollback fix; older trees do not have it.
            'CORAZA_SPOE_CONFIG_PATH': os.path.join(self.etc, 'coraza-spoe.cfg'),
            'CORAZA_SPOE_BACKUP_PATH': os.path.join(self.etc, 'coraza-spoe.cfg.backup'),
        }
        self._saved = {}
        for name, value in overrides.items():
            self._saved[name] = getattr(hm, name, None)
            setattr(hm, name, value)
        self.addCleanup(self._restore_globals)
        os.makedirs(hm.SSL_CERTS_DIR)

        # log_operation() appends to a hardcoded /var/log path. Injecting `open`
        # into the module namespace shadows the builtin for that module only
        # (module globals are searched before builtins), so the real
        # log_operation code still runs.
        real_open = open
        log_dir = self.tmp

        def _redirecting_open(path, *args, **kwargs):
            if isinstance(path, str) and path.startswith('/var/log/'):
                path = os.path.join(log_dir, os.path.basename(path))
            return real_open(path, *args, **kwargs)

        hm.open = _redirecting_open
        self.addCleanup(lambda: hm.__dict__.pop('open', None))

        hm.init_db()

    def _restore_globals(self):
        for name, value in self._saved.items():
            if value is None:
                hm.__dict__.pop(name, None)
            else:
                setattr(hm, name, value)

    # -- helpers ---------------------------------------------------------
    def add_domain(self, domain, backend_name, address='10.0.0.1'):
        with sqlite3.connect(hm.DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute('INSERT INTO domains (domain, ssl_enabled) VALUES (?, 0)',
                        (domain,))
            domain_id = cur.lastrowid
            cur.execute('INSERT INTO backends (name, domain_id) VALUES (?, ?)',
                        (backend_name, domain_id))
            backend_id = cur.lastrowid
            cur.execute(
                'INSERT INTO backend_servers '
                '(backend_id, server_name, server_address, server_port) '
                'VALUES (?, ?, ?, ?)',
                (backend_id, 'srv1', address, 8080))
            conn.commit()

    def block_ip(self, ip):
        with sqlite3.connect(hm.DB_FILE) as conn:
            conn.execute('INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)',
                         (ip, 'test'))
            conn.commit()

    def read(self, path):
        with open(path) as fh:
            return fh.read()

    def config_is_loadable(self):
        """True if HAProxy would accept the config currently on disk."""
        import subprocess
        return subprocess.run(
            ['haproxy', '-c', '-f', hm.HAPROXY_CONFIG_PATH],
            capture_output=True).returncode == 0

    def generate_good_config(self):
        self.add_domain('good.example.com', 'good_backend')
        hm.generate_config()
        self.assertTrue(self.config_is_loadable(),
                        'fixture precondition: first generated config must be valid')
        return self.read(hm.HAPROXY_CONFIG_PATH)

    def break_the_config(self):
        """Queue a domain whose rendered backend the validator rejects."""
        self.add_domain('bad.example.com', BROKEN_TOKEN + '_backend', '10.0.0.2')


class TestBackupOrdering(RollbackTestCase):

    def test_backup_is_taken_before_the_new_config_is_written(self):
        """The ordering invariant, asserted directly.

        Whatever create_backup() sees on disk must be the OLD config; if the
        write happens first the backup is a copy of the new config and rollback
        is meaningless.
        """
        good = self.generate_good_config()

        seen = {}
        real_create_backup = hm.create_backup

        def spy(*args, **kwargs):
            seen['config_on_disk'] = self.read(hm.HAPROXY_CONFIG_PATH)
            return real_create_backup(*args, **kwargs)

        hm.create_backup = spy
        self.addCleanup(setattr, hm, 'create_backup', real_create_backup)

        self.add_domain('second.example.com', 'second_backend', '10.0.0.3')
        hm.generate_config()

        self.assertIn('config_on_disk', seen,
                      'create_backup() was never called during generate_config()')
        self.assertEqual(
            seen['config_on_disk'], good,
            'create_backup() ran AFTER the new config was written - the backup '
            'is a copy of the new config, so rollback cannot undo anything')

    def test_backup_tracks_the_last_known_good_config(self):
        """After a change that validated AND loaded, the backup is that config.

        The rollback target is "the last configuration HAProxy actually ran",
        not "the file that happened to be there last time".
        """
        good = self.generate_good_config()
        self.add_domain('second.example.com', 'second_backend', '10.0.0.3')
        hm.generate_config()

        live = self.read(hm.HAPROXY_CONFIG_PATH)
        self.assertNotEqual(live, good, 'fixture sanity: the new config should differ')
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), live,
                         'the successful config was not recorded as known-good')

    def test_backup_is_not_promoted_when_the_change_fails(self):
        """A config that never loaded must not become the rollback target."""
        good = self.generate_good_config()
        self.break_the_config()
        with self.assertRaises(Exception):
            hm.generate_config()

        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), good,
                         'a config that failed validation was promoted to backup')


class TestRollbackEndToEnd(RollbackTestCase):

    def test_failed_validation_leaves_the_last_good_config_on_disk(self):
        good = self.generate_good_config()

        self.break_the_config()
        with self.assertRaises(Exception):
            hm.generate_config()

        on_disk = self.read(hm.HAPROXY_CONFIG_PATH)
        self.assertNotIn(BROKEN_TOKEN, on_disk,
                         'the rejected config is still on disk - rollback was a no-op')
        self.assertEqual(on_disk, good,
                         'on-disk config is not byte-identical to the last good one')

    def test_haproxy_would_still_start_after_a_failed_change(self):
        """The operational consequence: the edge can still come up."""
        self.generate_good_config()
        self.break_the_config()
        with self.assertRaises(Exception):
            hm.generate_config()

        self.assertTrue(self.config_is_loadable(),
                        'HAProxy would refuse to start with the config left on disk')
        with self.assertLogs('haproxy_manager', level='INFO') as captured:
            hm.start_haproxy()
        self.assertTrue(
            any('HAProxy started successfully' in line for line in captured.output),
            f'start_haproxy() did not succeed after rollback: {captured.output}')

    def test_blocked_ips_map_is_rolled_back_too(self):
        """generate_config() rewrites the map file before writing haproxy.cfg."""
        self.block_ip('192.0.2.10')
        self.generate_good_config()
        good_map = self.read(hm.BLOCKED_IPS_MAP_PATH)

        self.block_ip('198.51.100.20')
        self.break_the_config()
        with self.assertRaises(Exception):
            hm.generate_config()

        self.assertEqual(self.read(hm.BLOCKED_IPS_MAP_PATH), good_map,
                         'blocked IPs map was not rolled back with the config')

    def test_first_run_failure_reports_that_rollback_was_impossible(self):
        """No prior config: there is nothing to restore, and that must be said.

        A missing backup must never be reported as a successful restore, and it
        must never be turned into "restore an empty file".
        """
        self.break_the_config()
        with self.assertRaises(Exception) as ctx:
            hm.generate_config()

        self.assertIn('ROLLBACK FAILED', str(ctx.exception),
                      'a failed change with no backup was not reported as such')
        self.assertFalse(os.path.exists(hm.HAPROXY_BACKUP_PATH),
                         'a backup was fabricated from the broken config')
        # The broken config is deliberately left in place: start_haproxy() can
        # then detect it and try to regenerate. It must not be blanked.
        self.assertGreater(os.path.getsize(hm.HAPROXY_CONFIG_PATH), 0,
                           'config file was emptied instead of left for diagnosis')


class TestBackupPrimitives(RollbackTestCase):

    def test_restore_backup_distinguishes_missing_backup_from_success(self):
        restored, message = hm.restore_backup()
        self.assertFalse(restored,
                         'restore_backup() reported success with no backup present')
        self.assertIn('cannot roll back', message.lower())

        good = self.generate_good_config()
        with open(hm.HAPROXY_CONFIG_PATH, 'w') as fh:
            fh.write('scribbled over\n')

        restored, message = hm.restore_backup()
        self.assertTrue(restored, message)
        self.assertEqual(self.read(hm.HAPROXY_CONFIG_PATH), good)

    def test_a_successful_generation_records_a_rollback_target(self):
        """Even the first-ever generation must leave something to roll back to."""
        good = self.generate_good_config()
        self.assertTrue(
            os.path.exists(hm.HAPROXY_BACKUP_PATH),
            'after a successful reload there is still no known-good backup')
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), good)

    def test_a_broken_current_config_does_not_replace_a_good_backup(self):
        """The known-good marker.

        If the config already on disk is broken (previous failed write, manual
        edit), snapshotting it would make "rollback" mean "restore a different
        broken config". The older validated backup must survive.
        """
        good = self.generate_good_config()
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), good,
                         'fixture: a good backup should exist by now')

        with open(hm.HAPROXY_CONFIG_PATH, 'w') as fh:
            fh.write(f'garbage {BROKEN_TOKEN} config\n')

        ok, status = hm.create_backup()
        self.assertTrue(ok)
        self.assertEqual(status, 'kept_previous')
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), good,
                         'a broken config overwrote the known-good backup')

    def test_reload_does_not_take_its_own_backup(self):
        """reload_haproxy_safely() runs after the write, so it must not back up."""
        good = self.generate_good_config()
        with open(hm.HAPROXY_CONFIG_PATH, 'w') as fh:
            fh.write(f'broken {BROKEN_TOKEN}\n')

        success, message = hm.reload_haproxy_safely(backup_status='created')

        self.assertFalse(success)
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), good,
                         'reload_haproxy_safely() overwrote the good backup')
        self.assertEqual(self.read(hm.HAPROXY_CONFIG_PATH), good,
                         'reload_haproxy_safely() did not roll the config back')

    def test_unchanged_config_is_not_revalidated(self):
        """Fast path: if the backup already is the live config, do no work.

        generate_config() runs inside customer-facing API calls and
        `haproxy -c` is expensive on an edge with hundreds of certificates.
        """
        self.generate_good_config()

        calls = []
        real_validate = hm.validate_config_file
        hm.validate_config_file = lambda path: (calls.append(path),
                                                real_validate(path))[1]
        self.addCleanup(setattr, hm, 'validate_config_file', real_validate)

        ok, status = hm.create_backup()
        self.assertTrue(ok)
        self.assertEqual(status, 'created')
        self.assertEqual(calls, [],
                         'the unchanged live config was re-validated needlessly')

    def test_fast_path_does_not_hide_a_drifted_broken_config(self):
        """If the live config drifted from the backup, the gate must still run."""
        good = self.generate_good_config()
        with open(hm.HAPROXY_CONFIG_PATH, 'w') as fh:
            fh.write(f'hand edited {BROKEN_TOKEN}\n')

        ok, status = hm.create_backup()
        self.assertTrue(ok)
        self.assertEqual(status, 'kept_previous',
                         'a drifted broken config was silently accepted')
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), good)

    def test_backup_set_covers_every_file_generate_config_writes(self):
        """Derived, not restated.

        An earlier version of this test listed the three files it expected and
        checked they were in the backup set, so it could never have noticed a
        FOURTH file being added. Here the set of files generate_config() writes
        is observed (and, for env-gated branches this fixture cannot safely
        execute, read out of the source), and anything not backed up has to be
        on the documented exclusion list below.
        """
        # Written by generate_config() but deliberately NOT restorable, with
        # the reason. Everything else must be in the backup set: `haproxy -c`
        # validates the config as a set, so a file it loads that is not
        # restored alongside haproxy.cfg breaks rollback.
        excluded = {
            # Only ever created empty-when-missing (haproxy refuses to start
            # with an ACL -f pointing at a missing file); its contents are
            # owned by the /suspended API, not by generate_config(), so there
            # is nothing here for a config rollback to undo.
            'suspended_domains.list',
            # Generated once and then read, never rewritten with new content.
            # Its value is rendered INTO haproxy.cfg, so restoring an older
            # haproxy.cfg alongside the current secret file is consistent.
            'cluster-secret',
        }
        backed_up = {os.path.basename(p) for p, _ in hm._config_backup_pairs()}

        # 1. Observed: run a generation with every patchable optional branch on
        #    and see what actually changed on disk.
        self.add_domain('derive.example.com', 'derive_backend')
        os.environ['HAPROXY_CORAZA_SPOE_BACKEND'] = '127.0.0.1:9000'
        self.addCleanup(os.environ.pop, 'HAPROXY_CORAZA_SPOE_BACKEND', None)
        before = self._snapshot_etc()
        hm.generate_config()
        after = self._snapshot_etc()
        touched = {name for name, blob in after.items()
                   if before.get(name) != blob}
        self.assertIn('coraza-spoe.cfg', touched,
                      'fixture precondition: the Coraza branch did not run')

        # 2. Read out of the source: branches this fixture must not execute
        #    (suspension writes a hardcoded /etc/haproxy path that no test
        #    global can redirect) still have to be accounted for.
        touched |= {
            os.path.basename(m)
            for m in re.findall(r"'(/etc/haproxy/[\w.+-]+)'",
                                inspect.getsource(hm.generate_config))
        }

        unaccounted = touched - backed_up - excluded
        self.assertEqual(
            unaccounted, set(),
            f'generate_config() writes {sorted(unaccounted)}, which is neither '
            'in the backup set nor on the documented exclusion list - a '
            'rollback would restore a mixed-vintage config set')

    def _snapshot_etc(self):
        """Contents of every plain file in the fake /etc/haproxy.

        Skips the backup halves (they are the thing being maintained), the
        SQLite database and its journals, and the stats socket.
        """
        skip_prefixes = (os.path.basename(hm.DB_FILE),
                         os.path.basename(hm.HAPROXY_SOCKET_PATH))
        state = {}
        for name in os.listdir(self.etc):
            path = os.path.join(self.etc, name)
            if not os.path.isfile(path) or name.endswith('.backup'):
                continue
            if name.startswith(skip_prefixes):
                continue
            with open(path, 'rb') as fh:
                state[name] = fh.read()
        return state

    def test_coraza_spoe_config_round_trips(self):
        self.generate_good_config()
        with open(hm.CORAZA_SPOE_CONFIG_PATH, 'w') as fh:
            fh.write('spoe-good\n')
        hm.create_backup()
        with open(hm.CORAZA_SPOE_CONFIG_PATH, 'w') as fh:
            fh.write('spoe-broken\n')
        restored, message = hm.restore_backup()
        self.assertTrue(restored, message)
        self.assertEqual(self.read(hm.CORAZA_SPOE_CONFIG_PATH), 'spoe-good\n')


class TestAtomicWrite(RollbackTestCase):

    def test_write_is_atomic_and_preserves_mode(self):
        path = os.path.join(self.etc, 'atomic.cfg')
        with open(path, 'w') as fh:
            fh.write('old')
        os.chmod(path, 0o644)

        hm.write_config_atomically(path, 'new content\n')

        self.assertEqual(self.read(path), 'new content\n')
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o644))
        leftovers = [n for n in os.listdir(self.etc) if n.endswith('.tmp')]
        self.assertEqual(leftovers, [], f'temp files left behind: {leftovers}')

    def test_failed_write_leaves_the_previous_file_intact(self):
        path = os.path.join(self.etc, 'atomic.cfg')
        with open(path, 'w') as fh:
            fh.write('old content\n')

        # Anything that makes f.write() blow up mid-flight stands in for a full
        # disk / killed container. TypeError specifically, not Exception: a
        # bare assertRaises(Exception) also swallows the AttributeError raised
        # when write_config_atomically does not exist at all, so this test
        # passed against the pre-fix tree and would keep passing if the
        # function were deleted.
        with self.assertRaises(TypeError):
            hm.write_config_atomically(path, object())

        self.assertEqual(self.read(path), 'old content\n',
                         'a failed write clobbered the previous config')
        leftovers = [n for n in os.listdir(self.etc) if n.endswith('.tmp')]
        self.assertEqual(leftovers, [], f'temp files left behind: {leftovers}')


class TestBackupFailureGuard(RollbackTestCase):
    """generate_config() refuses to write when no rollback target could be taken."""

    def test_a_failed_backup_stops_the_config_from_being_written(self):
        good = self.generate_good_config()
        self.block_ip('192.0.2.10')
        hm.update_blocked_ips_map()
        good_map = self.read(hm.BLOCKED_IPS_MAP_PATH)

        real_create_backup = hm.create_backup
        hm.create_backup = lambda *a, **kw: (False, 'error')
        self.addCleanup(setattr, hm, 'create_backup', real_create_backup)

        self.add_domain('second.example.com', 'second_backend', '10.0.0.3')
        with self.assertRaises(Exception) as ctx:
            hm.generate_config()

        self.assertIn('Refusing to regenerate', str(ctx.exception),
                      'a backup failure was not reported as a refusal')
        self.assertEqual(
            self.read(hm.HAPROXY_CONFIG_PATH), good,
            'a new config was written even though the snapshot failed - a bad '
            'change could not have been rolled back')
        self.assertEqual(
            self.read(hm.BLOCKED_IPS_MAP_PATH), good_map,
            'the blocked IPs map was rewritten even though the snapshot failed')


class TestValidatorAvailability(RollbackTestCase):
    """'the validator could not run' is not the same as 'the config is bad'."""

    def _hide_the_haproxy_binary(self):
        empty = os.path.join(self.tmp, 'empty-bin')
        os.makedirs(empty, exist_ok=True)
        os.environ['PATH'] = empty
        # setUp's cleanup restores the original PATH.

    def test_a_missing_validator_is_unavailable_not_invalid(self):
        good = self.generate_good_config()
        self._hide_the_haproxy_binary()

        status, message = hm.validate_config_file(hm.HAPROXY_CONFIG_PATH)
        self.assertEqual(status, 'unavailable',
                         'a validator that could not run was reported as a '
                         f'verdict on the config ({status}: {message})')

        # And the consequence create_backup() draws from it: a config it could
        # not check is still snapshotted, because refusing would leave the box
        # with no rollback target at all. Contrast
        # test_a_broken_current_config_does_not_replace_a_good_backup, where a
        # real 'invalid' verdict yields 'kept_previous'.
        with open(hm.HAPROXY_CONFIG_PATH, 'w') as fh:
            fh.write('hand written, unverifiable\n')
        ok, status = hm.create_backup()
        self.assertTrue(ok)
        self.assertEqual(status, 'created',
                         'an unverifiable config was treated as a rejected one')
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH),
                         'hand written, unverifiable\n')
        self.assertNotEqual(self.read(hm.HAPROXY_BACKUP_PATH), good)


class TestFileComparison(RollbackTestCase):
    """The fast path compares bytes, not sizes."""

    def test_same_size_different_content_is_not_identical(self):
        a = os.path.join(self.etc, 'a')
        b = os.path.join(self.etc, 'b')
        with open(a, 'w') as fh:
            fh.write('aaaa\n')
        with open(b, 'w') as fh:
            fh.write('aaba\n')
        self.assertEqual(os.path.getsize(a), os.path.getsize(b),
                         'fixture: the two files must be the same size')
        self.assertFalse(hm._files_identical(a, b),
                         'two same-size files with different bytes compared equal')

    def test_a_same_size_drifted_config_still_hits_the_validation_gate(self):
        """The case the byte-compare exists for.

        A config edited in place without changing its length (one character
        swapped, a hostname replaced by another of the same width) must not be
        mistaken for the known-good backup and waved through.
        """
        good = self.generate_good_config()
        # Sized in BYTES, not characters: the rendered config contains
        # non-ASCII (em dashes in template comments), so len(str) would be
        # smaller than the file and this test would pass for the wrong reason.
        size = os.path.getsize(hm.HAPROXY_CONFIG_PATH)
        broken = f'# {BROKEN_TOKEN}\n'.encode()
        broken += b'#' * (size - len(broken) - 1) + b'\n'
        with open(hm.HAPROXY_CONFIG_PATH, 'wb') as fh:
            fh.write(broken)
        self.assertEqual(os.path.getsize(hm.HAPROXY_CONFIG_PATH), size,
                         'fixture: the drifted config must be the same size')

        ok, status = hm.create_backup()
        self.assertTrue(ok)
        self.assertEqual(
            status, 'kept_previous',
            'a same-size broken config was accepted as unchanged and skipped '
            'the validation gate')
        self.assertEqual(self.read(hm.HAPROXY_BACKUP_PATH), good,
                         'the known-good backup was overwritten')


class TestBlockedIpsMapWrites(RollbackTestCase):
    """blocked_ips.map is loaded by `haproxy -c`, so it gets the same care.

    Verified against HAProxy 2.8: with the map referenced by
    map_ip(/etc/haproxy/blocked_ips.map,0), a half-written final line makes the
    WHOLE configuration invalid ("'198.51.10' is not a valid IPv4 or IPv6
    address at line 2 of file ..."), not merely a dropped entry.
    """

    def test_the_map_goes_through_the_atomic_writer(self):
        seen = []
        real_write = hm.write_config_atomically

        def spy(path, content, *args, **kwargs):
            seen.append(path)
            return real_write(path, content, *args, **kwargs)

        hm.write_config_atomically = spy
        self.addCleanup(setattr, hm, 'write_config_atomically', real_write)

        self.block_ip('192.0.2.10')
        self.assertTrue(hm.update_blocked_ips_map())
        self.assertIn(hm.BLOCKED_IPS_MAP_PATH, seen,
                      'the blocked IPs map was written without the atomic '
                      'writer - a truncated map is a fatal config')

    def test_a_crash_before_the_rename_leaves_the_old_map_intact(self):
        self.block_ip('192.0.2.10')
        hm.update_blocked_ips_map()
        good_map = self.read(hm.BLOCKED_IPS_MAP_PATH)

        real_replace = os.replace

        def boom(src, dst, *args, **kwargs):
            if dst == hm.BLOCKED_IPS_MAP_PATH:
                raise OSError('simulated crash between write and rename')
            return real_replace(src, dst, *args, **kwargs)

        os.replace = boom
        self.addCleanup(setattr, os, 'replace', real_replace)

        self.block_ip('198.51.100.20')
        self.assertFalse(hm.update_blocked_ips_map(),
                         'a failed map write was reported as success')
        os.replace = real_replace

        self.assertEqual(
            self.read(hm.BLOCKED_IPS_MAP_PATH), good_map,
            'an interrupted map write clobbered the map HAProxy is running')
        leftovers = [n for n in os.listdir(self.etc) if n.endswith('.tmp')]
        self.assertEqual(leftovers, [], f'temp files left behind: {leftovers}')

    def test_a_malformed_map_is_not_recorded_as_known_good(self):
        """The map backup must stay something HAProxy would actually load."""
        self.generate_good_config()
        good_map = self.read(hm.BLOCKED_IPS_MAP_BACKUP_PATH)

        # Straight into the table, the way a bad row gets there in the first
        # place - the API route is not the only writer.
        self.block_ip('not-an-ip')
        hm.update_blocked_ips_map()

        self.assertEqual(
            self.read(hm.BLOCKED_IPS_MAP_BACKUP_PATH), good_map,
            'a map HAProxy cannot parse was promoted to the rollback target')

    def test_no_map_backup_is_fabricated_before_a_config_exists(self):
        """Nothing to stay in step with means nothing to write."""
        self.block_ip('192.0.2.10')
        self.assertTrue(hm.update_blocked_ips_map())
        self.assertFalse(
            os.path.exists(hm.BLOCKED_IPS_MAP_BACKUP_PATH),
            'a rollback target was invented out of a map write alone')


class TestValidationCost(RollbackTestCase):
    """`haproxy -c` runs are the customer-facing cost of a config change.

    generate_config() runs synchronously inside the API call that adds a
    domain, and on an edge with hundreds of certificates `haproxy -c` is the
    expensive part. These counts are the contract; changing them should be a
    deliberate decision, not a side effect.
    """

    def _count_validations(self, action):
        calls = []
        real_validate = hm.validate_config_file

        def spy(path):
            calls.append(path)
            return real_validate(path)

        hm.validate_config_file = spy
        try:
            action()
        finally:
            hm.validate_config_file = real_validate
        return len(calls)

    def test_blocking_an_ip_does_not_add_a_validation_to_the_next_change(self):
        self.generate_good_config()

        def add(domain, backend, address):
            self.add_domain(domain, backend, address)
            hm.generate_config()

        steady = self._count_validations(
            lambda: add('a.example.com', 'a_backend', '10.0.0.4'))
        self.assertEqual(
            steady, 1,
            'a steady-state config change should cost exactly one `haproxy -c` '
            '(the pre-reload gate); the known-good fast path should skip the '
            f'other one, but {steady} ran')

        # What POST /api/blocked-ips does: rewrite the map outside
        # generate_config(). This fleet blocks IPs automatically, so it happens
        # between most config changes.
        self.block_ip('192.0.2.10')
        hm.update_blocked_ips_map()

        after_block = self._count_validations(
            lambda: add('b.example.com', 'b_backend', '10.0.0.5'))
        self.assertEqual(
            after_block, steady,
            'an IP block left the map out of step with its backup, so the next '
            f'domain add paid {after_block} `haproxy -c` runs instead of '
            f'{steady} - on the customer-facing call')


if __name__ == '__main__':
    print(f"testing haproxy_manager from: {MODULE_DIR}")
    unittest.main(verbosity=2)
