#!/usr/bin/env python3
"""Contract test: what the stick tables STORE vs what the consumers READ.

Why this file exists
--------------------
`/api/security/stats` and `scripts/show-tarpit-ips.sh` spent their whole
existence reporting "Scan Count", "offense count" and "BLOCKED" figures parsed
out of `gpc0` and `gpc1`. **No stick table in this repo has ever stored a
general-purpose counter.** Every one of those numbers was fabricated, and an
operator was making decisions on them.

Nothing caught it, because each layer failed silently in a different way:

  * `int(parts[3])` on a positional split hit `exp=368842`, raised ValueError,
    and the loop `continue`d -- so the endpoint answered `active_threats: 0`
    with an empty list. "No threats" and "the parser is broken" looked
    identical.
  * The command went to the MASTER CLI socket without the `@1` worker prefix.
    HAProxy answered `Unknown command: 'show', but maybe one of the following
    ones is a better match: ...` and **socat still exited 0**, so the
    `returncode != 0` guard never fired. The reported `total_tracked_ips` was
    the line count of that help text (8) while the real table held 388 entries.
  * The shell consumers wrote `gpc0=${gpc0:-0}`, so a field that does not exist
    rendered as a confident zero.

The durable fix is not "parse better" -- it is making the template and its
consumers unable to drift apart without something going red. That is this file.

What it enforces
----------------
  1. `STICK_TABLE_FIELD_CONTRACT` in haproxy_manager.py equals, exactly and in
     both directions, the `store` clauses in the rendered templates.
  2. Every shell consumer's `EXPECTED_FIELDS=(...)` array equals the contract.
  3. A captured sample of REAL `show table` output from the live edge parses to
     exactly the contract's fields plus the entry metadata -- so the contract
     describes reality, not just itself.
  4. The loud-failure behaviour: `read_stick_table()` RAISES on a rejected
     command, on a non-table response, and on a row missing a contract field.
     It must never answer zeros. Guard 4 is the one that would have caught the
     original bug on day one.
  5. No `store` clause names a general-purpose counter, and no template tracks
     one -- the state this repo is actually in, asserted rather than assumed.

Assertions about the TEMPLATES go through `rule_lines()`, which strips comments
before matching. These templates quote their own rules in prose at length; a
bare `assertIn` over the rendered text passes just as happily against a rule
that has been commented out. Same lesson, and same helper, as
scripts/test-wpadmin-gate.py.

Runs fully offline -- no HAProxy, no socket, no network.

Running
-------
    python3 scripts/test-stick-table-contract.py
"""

import os
import re
import sys
import logging
import tempfile
import unittest

MODULE_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
)
os.chdir(MODULE_DIR)
sys.path.insert(0, MODULE_DIR)

_LOG_DIR = tempfile.mkdtemp(prefix='haproxy-mgr-test-logs-')
_real_file_handler = logging.FileHandler
logging.FileHandler = (
    lambda filename, *a, **kw: _real_file_handler(
        os.path.join(_LOG_DIR, os.path.basename(filename)), *a, **kw)
)

import haproxy_manager  # noqa: E402


# ---------------------------------------------------------------------------
# A captured sample of REAL output, so this test can assert against reality
# without a live socket.
#
# Provenance: `echo "@1 show table web" | socat stdio /tmp/haproxy-cli` inside
# the haproxy-manager container on whp01, 2026-08-22, HAProxy 3.0.11. Rows
# trimmed for length; format byte-for-byte as emitted.
#
# Note what is and is NOT here: no gpc0, no gpc1, no gpc(N), no gpc_rate, no
# glitch_rate. Note also that field windows come back in MILLISECONDS
# (`conn_rate(10000)`), not the `10s` the template writes -- a consumer that
# labels the raw number "10s" is off by a factor of 1000.
# ---------------------------------------------------------------------------
LIVE_TABLE_SAMPLE = """\
# table: web, type: ip, size:204800, used:388
0x7f6e5447e728: key=17.58.57.102 use=0 exp=368842 shard=0 conn_rate(10000)=0 conn_cur=0 http_req_rate(10000)=0 http_err_rate(30000)=0
0x7f6e541cf7c8: key=43.173.182.9 use=0 exp=171404 shard=0 conn_rate(10000)=0 conn_cur=0 http_req_rate(10000)=0 http_err_rate(30000)=0
0x7f6e5547f528: key=95.129.255.180 use=0 exp=590639 shard=0 conn_rate(10000)=1 conn_cur=0 http_req_rate(10000)=1 http_err_rate(30000)=0
0x7f6e5447e488: key=5.9.105.254 use=0 exp=556277 shard=0 conn_rate(10000)=0 conn_cur=0 http_req_rate(10000)=0 http_err_rate(30000)=1
"""

# The verbatim reply the MASTER CLI socket gives to an unprefixed worker
# command. Captured the same way. socat exits 0 on this -- which is the entire
# reason haproxy_cli() inspects the body.
MASTER_SOCKET_REJECTION = """\
Unknown command: 'show', but maybe one of the following ones is a better match:
  show cli level                          : display the level of the current CLI session
  show cli sockets                        : dump list of cli sockets
  show proc                               : show processes status
  show startup-logs                       : report logs emitted during HAProxy startup
  show version                            : show version of the current process
  help [<command>]                        : list matching or all commands
  prompt [timed]                          : toggle interactive mode with prompt
  quit                                    : disconnect
"""

# Anything matching these in a `store` clause is a general-purpose counter.
GPC_PATTERN = re.compile(r'\bgpc|glitch')

# Shell consumers that must declare their field expectations as a single
# EXPECTED_FIELDS array, and the table each one reads.
SHELL_CONSUMERS = {
    'scripts/show-edge-ip-rates.sh': 'web',
}

EXPECTED_FIELDS_RE = re.compile(r'^\s*EXPECTED_FIELDS=\(([^)]*)\)\s*$', re.M)


def rule_lines(cfg, needle):
    """Comment-stripped config lines containing `needle`.

    A line that is entirely a comment is dropped; a line mixing config with a
    trailing comment is truncated at the first ' #' before matching. Without
    this, every assertion below would pass against a rule that had been
    commented out but whose text survived in the surrounding prose -- and these
    templates quote their own rules in prose constantly. See
    scripts/test-wpadmin-gate.py, where a mutation audit proved the point.
    """
    out = []
    for raw in cfg.split('\n'):
        stripped = raw.strip()
        if stripped and not stripped.startswith('#'):
            code = stripped.split(' #', 1)[0].rstrip()
            if code and needle in code:
                out.append(code)
    return out


def render_listener():
    return haproxy_manager.template_env.get_template('hap_listener.tpl').render(
        crt_path='/etc/haproxy/certs',
        suspension_enabled=False,
        coraza_spoe_backend=None,
    )


def render_security_tables():
    return haproxy_manager.template_env.get_template('hap_security_tables.tpl').render()


def stick_tables_from(cfg):
    """{table name: (field, ...)} for every stick-table declared in `cfg`.

    A stick-table takes the name of the frontend/backend/listen section that
    declares it -- that name is what `show table <name>` wants, so the section
    header is part of the contract, not incidental. Section headers and
    stick-table lines are both read comment-stripped.
    """
    tables = {}
    section = None
    for raw in cfg.split('\n'):
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        code = stripped.split(' #', 1)[0].rstrip()
        header = re.match(r'^(frontend|backend|listen)\s+(\S+)', code)
        if header:
            section = header.group(2)
            continue
        if code.startswith('stick-table'):
            store = re.search(r'\bstore\s+(\S+)', code)
            if not store:
                raise AssertionError(
                    'stick-table in section %r has no `store` clause: %r'
                    % (section, code))
            if section is None:
                raise AssertionError(
                    'stick-table declared outside any section: %r' % code)
            # store is a comma-separated list; each item is name or name(window)
            fields = tuple(item.split('(')[0]
                           for item in store.group(1).split(','))
            tables[section] = fields
    return tables


def all_template_stick_tables():
    tables = {}
    for cfg in (render_listener(), render_security_tables()):
        for name, fields in stick_tables_from(cfg).items():
            if name in tables:
                raise AssertionError('stick table %r declared twice' % name)
            tables[name] = fields
    return tables


class StickTableContract(unittest.TestCase):
    """Guard 1 + 5: the templates and the Python contract, held together."""

    def setUp(self):
        self.templates = all_template_stick_tables()
        self.contract = haproxy_manager.STICK_TABLE_FIELD_CONTRACT

    def test_templates_actually_declare_stick_tables(self):
        """Guard the guard: an empty parse would make every other check vacuous."""
        self.assertTrue(self.templates,
                        'parsed no stick tables out of the templates at all -- '
                        'stick_tables_from() is broken, not the templates')

    def test_same_table_names(self):
        self.assertEqual(
            sorted(self.templates), sorted(self.contract),
            'STICK_TABLE_FIELD_CONTRACT and the templates disagree on WHICH '
            'stick tables exist. Add/remove the table in both places.')

    def test_same_fields_per_table(self):
        for table in sorted(self.templates):
            with self.subTest(table=table):
                self.assertEqual(
                    sorted(self.templates[table]),
                    sorted(self.contract.get(table, ())),
                    "stick table %r stores %s but STICK_TABLE_FIELD_CONTRACT "
                    "claims %s. Whichever is wrong, a consumer is about to read "
                    "a field that is never populated -- which is the bug this "
                    "test exists for." % (table,
                                          list(self.templates[table]),
                                          list(self.contract.get(table, ()))))

    def test_web_table_is_the_one_the_api_reads(self):
        self.assertIn('web', self.contract)
        self.assertIn('web', self.templates)

    def test_no_general_purpose_counters_are_stored(self):
        """The state of the world today, asserted rather than assumed.

        If a gpc/glitch counter is ever genuinely added to a template, this
        test is the place to update -- and updating it forces whoever does so
        to also add the field to STICK_TABLE_FIELD_CONTRACT (test_same_fields_
        per_table) and to the shell consumers (test_shell_consumers_match_
        contract). That chain is the point: a counter cannot appear in a
        consumer without existing in the table, and cannot appear in the table
        without the consumers being updated.
        """
        for table, fields in self.templates.items():
            for field in fields:
                self.assertIsNone(
                    GPC_PATTERN.search(field),
                    'stick table %r now stores %r. Update this test, '
                    'STICK_TABLE_FIELD_CONTRACT, and every consumer.'
                    % (table, field))

    def test_track_sc_counters_have_a_table_each(self):
        """Every `track-scN ... table X` names a table that really exists.

        A typo here is invisible to `haproxy -c` only in the sense that it is
        NOT -- but it is invisible to the consumers, which would query a table
        that is never written.
        """
        cfg = render_listener()
        for line in rule_lines(cfg, 'track-sc'):
            named = re.search(r'\btable\s+(\S+)', line)
            if named:
                self.assertIn(
                    named.group(1), self.templates,
                    'track-sc rule references undeclared table %r: %r'
                    % (named.group(1), line))

    def test_sc_counter_indices_fit_haproxys_limit(self):
        """sc0/sc1/sc2 are all HAProxy gives us by default.

        `tune.stick-counters` defaults to 3. A `track-sc3` without raising it
        is a config-time failure, and the templates' own comments assume the
        limit -- so assert it rather than leaving it as folklore.
        """
        cfg = render_listener() + '\n' + render_security_tables()
        raised = rule_lines(cfg, 'tune.stick-counters')
        limit = 3
        if raised:
            limit = int(re.search(r'(\d+)', raised[-1]).group(1))
        for line in rule_lines(cfg, 'track-sc'):
            idx = int(re.search(r'track-sc(\d+)', line).group(1))
            self.assertLess(
                idx, limit,
                'track-sc%d exceeds tune.stick-counters (%d): %r'
                % (idx, limit, line))


class ShellConsumerContract(unittest.TestCase):
    """Guard 2: the shell consumers cannot drift from the contract."""

    def test_shell_consumers_match_contract(self):
        for path, table in sorted(SHELL_CONSUMERS.items()):
            with self.subTest(script=path):
                full = os.path.join(MODULE_DIR, path)
                self.assertTrue(os.path.exists(full),
                                '%s is missing; it is a declared consumer of '
                                'stick table %r' % (path, table))
                with open(full) as fh:
                    src = fh.read()
                m = EXPECTED_FIELDS_RE.search(src)
                self.assertIsNotNone(
                    m, '%s must declare its field expectations once as a '
                       'single-line `EXPECTED_FIELDS=(a b c)` array so this '
                       'test can hold it to the template' % path)
                declared = sorted(m.group(1).split())
                self.assertEqual(
                    declared,
                    sorted(haproxy_manager.STICK_TABLE_FIELD_CONTRACT[table]),
                    '%s reads %s but stick table %r stores %s'
                    % (path, declared, table,
                       sorted(haproxy_manager.STICK_TABLE_FIELD_CONTRACT[table])))

    def test_retired_script_no_longer_parses_phantom_counters(self):
        """show-tarpit-ips.sh may explain gpc0/gpc1; it may not extract them.

        The shim is allowed -- encouraged -- to name the fields in prose so an
        operator who runs it learns why its numbers went away. What it must not
        do is go back to pulling values out of them.
        """
        path = os.path.join(MODULE_DIR, 'scripts/show-tarpit-ips.sh')
        if not os.path.exists(path):
            self.skipTest('show-tarpit-ips.sh has been removed outright')
        with open(path) as fh:
            lines = fh.readlines()
        for raw in lines:
            stripped = raw.strip()
            if not stripped or stripped.startswith('#'):
                continue
            code = stripped.split(' #', 1)[0]
            self.assertIsNone(
                re.search(r"grep -o ['\"]?gpc|gpc[0-9]*=\$|sc_get_gpc|sc-inc-gpc", code),
                'show-tarpit-ips.sh is extracting a general-purpose counter '
                'again: %r' % stripped)


class LiveSampleParses(unittest.TestCase):
    """Guard 3: the contract describes real HAProxy output, not just itself."""

    def test_header_parses(self):
        header, entries = self._read()
        self.assertEqual(header['name'], 'web')
        self.assertEqual(header['type'], 'ip')
        self.assertEqual(header['size'], 204800)
        self.assertEqual(header['used'], 388)
        self.assertEqual(len(entries), 4)

    def test_sample_fields_are_exactly_contract_plus_metadata(self):
        expected = set(haproxy_manager.STICK_TABLE_FIELD_CONTRACT['web'])
        expected |= set(haproxy_manager.STICK_TABLE_ENTRY_META)
        _, entries = self._read()
        for line, fields in entries:
            self.assertEqual(
                set(fields), expected,
                'real `show table web` output carries %s, contract+metadata '
                'expects %s. Row: %r'
                % (sorted(fields), sorted(expected), line))

    def test_key_is_the_ip_not_the_allocation_pointer(self):
        """The original bug read parts[0] -- the `0x...:` pointer -- as the IP."""
        _, entries = self._read()
        ips = [f['key']['value'] for _, f in entries]
        self.assertIn('95.129.255.180', ips)
        for ip in ips:
            self.assertFalse(ip.startswith('0x'),
                             'parsed a memory address as an IP: %r' % ip)

    def test_windows_are_milliseconds(self):
        """HAProxy reports `conn_rate(10000)` for a `conn_rate(10s)` store.

        Asserted because labelling that raw 10000 as "10s" (or as seconds) is
        an easy and completely silent way to be wrong by 1000x in the panel.
        """
        _, entries = self._read()
        _, fields = entries[0]
        self.assertEqual(fields['conn_rate']['window_ms'], 10000)
        self.assertEqual(fields['http_req_rate']['window_ms'], 10000)
        self.assertEqual(fields['http_err_rate']['window_ms'], 30000)
        self.assertIsNone(fields['conn_cur']['window_ms'],
                          'conn_cur is a gauge, not a rate; it has no window')

    def test_values_are_the_real_ones(self):
        _, entries = self._read()
        by_ip = {f['key']['value']: f for _, f in entries}
        self.assertEqual(by_ip['95.129.255.180']['http_req_rate']['value'], '1')
        self.assertEqual(by_ip['5.9.105.254']['http_err_rate']['value'], '1')
        self.assertEqual(by_ip['17.58.57.102']['http_req_rate']['value'], '0')

    def _read(self):
        return _read_table_from(LIVE_TABLE_SAMPLE)


class FailsLoudly(unittest.TestCase):
    """Guard 4: every way this can go wrong must raise, never return zeros.

    This is the guard that would have caught the original bug immediately. Each
    case below is a real response the old code accepted silently.
    """

    def test_master_socket_rejection_is_not_data(self):
        """The exact reply that used to be reported as `total_tracked_ips: 8`."""
        with self.assertRaises(haproxy_manager.HaproxyCliError) as ctx:
            _read_table_from(MASTER_SOCKET_REJECTION)
        self.assertIn('not a stick-table dump', str(ctx.exception))

    def test_socat_exit_zero_does_not_mean_success(self):
        """haproxy_cli() must reject on the BODY, not the exit status.

        socat returns 0 for every response above -- the rejection is only ever
        visible in the text.
        """
        self.assertTrue(
            haproxy_manager._cli_response_is_error(MASTER_SOCKET_REJECTION))
        self.assertTrue(
            haproxy_manager._cli_response_is_error('No such table\n'))
        self.assertTrue(
            haproxy_manager._cli_response_is_error('Permission denied\n'))
        self.assertFalse(
            haproxy_manager._cli_response_is_error(LIVE_TABLE_SAMPLE))

    def test_missing_contract_field_raises_and_names_it(self):
        """A field the table stopped storing must not silently become 0."""
        degraded = LIVE_TABLE_SAMPLE.replace(' http_err_rate(30000)=0', '')
        with self.assertRaises(haproxy_manager.HaproxyCliError) as ctx:
            _read_table_from(degraded)
        msg = str(ctx.exception)
        self.assertIn('http_err_rate', msg,
                      'the error must name the missing field')
        self.assertIn('drifted', msg,
                      'the error must say what actually went wrong')

    def test_empty_response_raises(self):
        with self.assertRaises(haproxy_manager.HaproxyCliError):
            _read_table_from('')

    def test_row_without_key_raises(self):
        broken = LIVE_TABLE_SAMPLE.replace('key=17.58.57.102 ', '')
        with self.assertRaises(haproxy_manager.HaproxyCliError) as ctx:
            _read_table_from(broken)
        self.assertIn('no key=', str(ctx.exception))

    def test_unknown_table_raises_before_touching_the_socket(self):
        """Querying a table with no contract is a programming error, not a 0."""
        with self.assertRaises(haproxy_manager.HaproxyCliError) as ctx:
            haproxy_manager.read_stick_table('does_not_exist')
        self.assertIn('no field contract', str(ctx.exception))

    def test_empty_table_is_not_an_error(self):
        """A table with zero entries is a legitimate, distinguishable result."""
        header, entries = _read_table_from(
            '# table: web, type: ip, size:204800, used:0\n')
        self.assertEqual(header['used'], 0)
        self.assertEqual(entries, [])


def _read_table_from(response, table='web'):
    """Run read_stick_table() against a canned response instead of a socket."""
    real = haproxy_manager.haproxy_cli
    haproxy_manager.haproxy_cli = lambda cmd, worker=False, timeout=None: response
    try:
        return haproxy_manager.read_stick_table(table)
    finally:
        haproxy_manager.haproxy_cli = real


if __name__ == '__main__':
    unittest.main(verbosity=2)
