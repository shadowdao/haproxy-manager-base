#!/usr/bin/env python3
"""Contract test: the runtime-map fast path (blocked IPs).

Why this file exists
--------------------
`add_ip_to_runtime_map()` and `remove_ip_from_runtime_map()` spent their whole
existence sending

    add map #0 <ip> 1
    del map #0 <ip>

to `/tmp/haproxy-cli` and returning True whenever socat exited 0. Neither
command has ever worked. Two independent defects:

  * **No `@1` prefix.** `/tmp/haproxy-cli` is HAProxy's MASTER CLI socket; map
    commands are worker commands. The master answers `Unknown command: 'add',
    but maybe one of the following ones is a better match: ...` -- and **socat
    still exits 0**, so `result.returncode == 0` was true and the function
    logged "Added IP x to runtime map".
  * **`#0` is not a valid map id.** Ids are assigned at config-parse time and
    move on every config regeneration; on the live edge `blocked_ips.map` is
    id 37 and `trusted_ips.map` is 10. There is no id 0. Any hardcoded number
    is wrong -- the map must be referenced by its FILE PATH, which is what
    haproxy.cfg itself names in `map_ip(/etc/haproxy/blocked_ips.map,0)`.

And a third silence that makes a response-body check alone insufficient:
`@1 add map #0 <ip> 1` returns an **empty body**, exit 0, and adds nothing
anywhere -- while `@1 del map #0 <ip>` answers `Unknown map identifier.`. The
add path can therefore only be trusted after reading the entry back.

IP blocking still worked, because `update_blocked_ips_map()` rewrites
`/etc/haproxy/blocked_ips.map` and the callers reload HAProxy, which re-reads
it. The FILE is authoritative; this is the no-reload fast path, and it has
never once run while reporting that it did.

What it enforces
----------------
  1. The command strings actually sent: `@1` prefix first, map referenced by
     PATH and never by `#<id>`, and the value `1` that
     `map_ip(...,0) -m int gt 0` requires.
  2. Every captured rejection is classified as FAILURE (returns False), not
     success -- including the two that carry no error text at all.
  3. Success is only reported when the entry reads back in the state asked
     for. Not the exit status, not an empty reply.
  4. No source in this repo builds a map command with a `#<id>` reference.
     Comments may describe the old form; code may not use it.

Runs fully offline: `_cli_send()` is replaced, so no socket, no socat, no
HAProxy, no network.

Running
-------
    python3 scripts/test-runtime-map-contract.py
"""

import ast
import io
import os
import re
import sys
import glob
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

logging.getLogger().setLevel(logging.CRITICAL)

MAP = haproxy_manager.BLOCKED_IPS_MAP_PATH
IP = '192.0.2.77'

# ---------------------------------------------------------------------------
# Responses captured VERBATIM from the haproxy-manager container on the live
# edge (HAProxy 3.0.11, 2026-08-22). socat exited 0 for every single one of
# them, which is the entire reason none of this is decided on exit status.
# ---------------------------------------------------------------------------

# What the MASTER socket answers to an unprefixed `add map ...` -- i.e. the
# reply the old code read as success.
MASTER_REJECTS_ADD = """\
Unknown command: 'add', but maybe one of the following ones is a better match:
  @!<pid>                                 : send a command to the <pid> process
  @master                                 : send a command to the master process
  hard-reload                             : achieve a hard-reload (-st) of haproxy
  reload                                  : achieve a soft-reload (-sf) of haproxy
  user                                    : lower the level of the current CLI session to user
  help [<command>]                        : list matching or all commands
  prompt [timed]                          : toggle interactive mode with prompt
  quit                                    : disconnect
"""

MASTER_REJECTS_DEL = MASTER_REJECTS_ADD.replace("'add'", "'del'")

# `@1 del map #0 <ip>` / `@1 get map /etc/haproxy/nope.map <ip>`.
UNKNOWN_MAP_IDENTIFIER = 'Unknown map identifier. Please use #<id> or <file>.\n'

# `@1 add map <map> <ip>` with the value omitted (as the old docs showed).
ADD_MAP_MISSING_VALUE = (
    "'add map' expects three parameters (map identifier, key and value) or one "
    "parameter (map identifier) and a payload\n")

# `@1 del map <map> <ip>` for a key the runtime map does not hold.
KEY_NOT_FOUND = 'Key not found.\n'

# A successful mutation. THIS IS THE WHOLE PROBLEM: it is byte-for-byte what
# `@1 add map #0 <ip> 1` also returns while adding nothing at all.
MUTATION_OK = ''

GET_FOUND = ('type=ip, case=sensitive, found=yes, idx=tree, key="%s", '
             'value="1", type="str"\n' % IP)
GET_NOT_FOUND = 'type=ip, case=sensitive, found=no\n'
# `@1 get map #0 <ip>` -- "found", but with no value. haproxy.cfg matches with
# `-m int gt 0`, so an entry like this does NOT block.
GET_FOUND_NO_VALUE = ('type=ip, case=sensitive, found=yes, idx=tree, key="%s", '
                      'value=none\n' % IP)

SHOW_MAP_SAMPLE = (
    '0x7f6e5a788700 101.36.109.130 1\n'
    '0x7f6e5a788780 101.47.140.218 1\n'
    '0x7f6e5a1fd500 %s 1\n' % IP)


class FakeSocket(object):
    """Replaces _cli_send(). Records every command, answers from a script.

    `script` is a list of (substring, response) pairs, consulted in order; the
    first whose substring appears in the command wins. Anything unmatched is
    an explicit test bug, not a silent default.
    """

    def __init__(self, script):
        self.script = script
        self.sent = []

    def __call__(self, command, socket_path, timeout):
        self.sent.append(command)
        for needle, response in self.script:
            if needle in command:
                return response
        raise AssertionError('test script has no response for %r' % command)


def with_socket(script):
    """Install a FakeSocket for the duration of a `with` block."""
    class _Ctx(object):
        def __enter__(self):
            self.fake = FakeSocket(script)
            self._real = haproxy_manager._cli_send
            haproxy_manager._cli_send = self.fake
            return self.fake

        def __exit__(self, *exc):
            haproxy_manager._cli_send = self._real
            return False
    return _Ctx()


# Every command the happy path needs, in the order the code issues them.
HAPPY_ADD = [('get map', GET_FOUND), ('add map', MUTATION_OK)]
HAPPY_DEL = [('get map', GET_NOT_FOUND), ('del map', MUTATION_OK)]


class CommandsAreWellFormed(unittest.TestCase):
    """Guard 1: the exact bytes on the wire.

    Both original defects are visible here and nowhere else -- a `#0` map
    reference and a missing `@1` are perfectly ordinary-looking Python.
    """

    def test_add_sends_worker_prefixed_path_referenced_command(self):
        with with_socket(HAPPY_ADD) as fake:
            self.assertTrue(haproxy_manager.add_ip_to_runtime_map(IP))
        self.assertEqual(fake.sent[0], '@1 add map %s %s 1' % (MAP, IP))

    def test_del_sends_worker_prefixed_path_referenced_command(self):
        with with_socket(HAPPY_DEL) as fake:
            self.assertTrue(haproxy_manager.remove_ip_from_runtime_map(IP))
        self.assertEqual(fake.sent[0], '@1 del map %s %s' % (MAP, IP))

    def test_every_command_is_tried_on_the_worker_first(self):
        """`/tmp/haproxy-cli` is the MASTER socket; bare map commands 404."""
        for run in (lambda: haproxy_manager.add_ip_to_runtime_map(IP),
                    lambda: haproxy_manager.remove_ip_from_runtime_map(IP)):
            with with_socket(HAPPY_ADD + HAPPY_DEL) as fake:
                run()
            for command in fake.sent:
                self.assertTrue(command.startswith('@1 '),
                                '%r is missing the @1 worker prefix' % command)

    def test_no_command_references_a_map_by_id(self):
        """Map ids move on every config regeneration. Path, always."""
        script = HAPPY_ADD + HAPPY_DEL + [('show map', SHOW_MAP_SAMPLE)]
        with with_socket(script) as fake:
            haproxy_manager.add_ip_to_runtime_map(IP)
            haproxy_manager.remove_ip_from_runtime_map(IP)
            haproxy_manager.runtime_map_keys(MAP)
        for command in fake.sent:
            self.assertNotRegex(
                command, r'\bmap\s+#',
                '%r references a map by id; ids are not stable' % command)
            self.assertIn(MAP, command,
                          '%r does not name the map file' % command)

    def test_add_carries_the_value_the_config_matches_on(self):
        """`map_ip(...,0) -m int gt 0`: a valueless entry does not block."""
        self.assertEqual(haproxy_manager.BLOCKED_IPS_MAP_VALUE, '1')
        with with_socket(HAPPY_ADD) as fake:
            haproxy_manager.add_ip_to_runtime_map(IP)
        self.assertTrue(fake.sent[0].endswith(' %s 1' % IP),
                        '%r has no value; HAProxy rejects it' % fake.sent[0])


class RejectionIsFailure(unittest.TestCase):
    """Guard 2+3: nothing may report success unless the map really changed.

    Every response below was returned by the live socket with **exit code 0**.
    The old code returned True for all of them.
    """

    def test_master_socket_rejection_of_add_is_failure(self):
        with with_socket([('get map', GET_NOT_FOUND), ('add map', MASTER_REJECTS_ADD)]):
            self.assertFalse(haproxy_manager.add_ip_to_runtime_map(IP))

    def test_master_socket_rejection_of_del_is_failure(self):
        with with_socket([('get map', GET_FOUND), ('del map', MASTER_REJECTS_DEL)]):
            self.assertFalse(haproxy_manager.remove_ip_from_runtime_map(IP))

    def test_unknown_map_identifier_is_failure(self):
        with with_socket([('get map', GET_NOT_FOUND), ('add map', UNKNOWN_MAP_IDENTIFIER)]):
            self.assertFalse(haproxy_manager.add_ip_to_runtime_map(IP))
        with with_socket([('get map', GET_FOUND), ('del map', UNKNOWN_MAP_IDENTIFIER)]):
            self.assertFalse(haproxy_manager.remove_ip_from_runtime_map(IP))

    def test_missing_value_rejection_is_failure(self):
        """Carries no marker word at all -- caught by 'a mutation says nothing'."""
        with with_socket([('get map', GET_NOT_FOUND), ('add map', ADD_MAP_MISSING_VALUE)]):
            self.assertFalse(haproxy_manager.add_ip_to_runtime_map(IP))

    def test_silent_noop_add_is_failure(self):
        """The `#0` failure mode: accepted, empty reply, nothing added.

        Nothing in the response distinguishes this from success. Only the
        read-back does -- which is why the read-back is not optional.
        """
        with with_socket([('get map', GET_NOT_FOUND), ('add map', MUTATION_OK)]):
            self.assertFalse(haproxy_manager.add_ip_to_runtime_map(IP))

    def test_add_that_lands_without_a_value_is_failure(self):
        with with_socket([('get map', GET_FOUND_NO_VALUE), ('add map', MUTATION_OK)]):
            self.assertFalse(haproxy_manager.add_ip_to_runtime_map(IP))

    def test_del_that_leaves_the_key_behind_is_failure(self):
        with with_socket([('get map', GET_FOUND), ('del map', MUTATION_OK)]):
            self.assertFalse(haproxy_manager.remove_ip_from_runtime_map(IP))

    def test_key_not_found_on_del_is_the_requested_end_state(self):
        """Not a failure: the runtime map already lacks the key."""
        with with_socket([('get map', GET_NOT_FOUND), ('del map', KEY_NOT_FOUND)]):
            self.assertTrue(haproxy_manager.remove_ip_from_runtime_map(IP))

    def test_verified_success_is_reported_as_success(self):
        with with_socket(HAPPY_ADD):
            self.assertTrue(haproxy_manager.add_ip_to_runtime_map(IP))
        with with_socket(HAPPY_DEL):
            self.assertTrue(haproxy_manager.remove_ip_from_runtime_map(IP))

    def test_a_runtime_failure_never_raises_into_the_request_handler(self):
        """The map file + reload still enforces the block; degrade, don't 500."""
        with with_socket([('get map', GET_NOT_FOUND), ('add map', MASTER_REJECTS_ADD)]):
            self.assertIs(haproxy_manager.add_ip_to_runtime_map(IP), False)

    def test_mutations_are_checked_for_an_empty_body_not_a_marker_list(self):
        """_HAPROXY_CLI_ERROR_MARKERS can only know rejections already seen."""
        with self.assertRaises(haproxy_manager.HaproxyCliError):
            with with_socket([('add map', 'something nobody has ever seen\n')]):
                haproxy_manager.haproxy_cli('add map %s x 1' % MAP,
                                            worker=True, expect_empty=True)

    def test_the_new_error_markers_are_recognised(self):
        for response in (UNKNOWN_MAP_IDENTIFIER, KEY_NOT_FOUND,
                         MASTER_REJECTS_ADD):
            self.assertTrue(haproxy_manager._cli_response_is_error(response),
                            '%r must be classified as an error' % response[:40])
        for response in (GET_FOUND, GET_NOT_FOUND, SHOW_MAP_SAMPLE):
            self.assertFalse(haproxy_manager._cli_response_is_error(response),
                             '%r is data, not an error' % response[:40])

    def test_socat_exit_zero_carries_no_information(self):
        """FakeSocket never signals failure any other way, and neither did socat."""
        with with_socket([('get map', GET_NOT_FOUND), ('add map', MASTER_REJECTS_ADD)]) as fake:
            self.assertFalse(haproxy_manager.add_ip_to_runtime_map(IP))
        self.assertTrue(fake.sent, 'the command was sent and "succeeded" at the '
                                   'process level; only the body says otherwise')


class ReadBack(unittest.TestCase):
    """The read-back primitives the guarantees above rest on."""

    def test_lookup_reports_found_with_value(self):
        with with_socket([('get map', GET_FOUND)]):
            self.assertEqual(haproxy_manager.runtime_map_lookup(MAP, IP),
                             (True, '1'))

    def test_lookup_reports_not_found(self):
        with with_socket([('get map', GET_NOT_FOUND)]):
            self.assertEqual(haproxy_manager.runtime_map_lookup(MAP, IP),
                             (False, None))

    def test_lookup_raises_on_a_rejected_reference(self):
        with with_socket([('get map', UNKNOWN_MAP_IDENTIFIER)]):
            with self.assertRaises(haproxy_manager.HaproxyCliError):
                haproxy_manager.runtime_map_lookup(MAP, IP)

    def test_keys_parses_show_map_output(self):
        with with_socket([('show map', SHOW_MAP_SAMPLE)]):
            self.assertEqual(
                haproxy_manager.runtime_map_keys(MAP),
                {'101.36.109.130', '101.47.140.218', IP})

    def test_empty_map_is_not_a_rejection(self):
        with with_socket([('show map', '')]):
            self.assertEqual(haproxy_manager.runtime_map_keys(MAP), set())

    def test_rejected_show_map_still_raises(self):
        with with_socket([('show map', UNKNOWN_MAP_IDENTIFIER)]):
            with self.assertRaises(haproxy_manager.HaproxyCliError):
                haproxy_manager.runtime_map_keys(MAP)


MAP_BY_ID_RE = re.compile(r'\b(?:add|del|clear|show|get)\s+map\s+#')


class NoSourceBuildsAMapIdCommand(unittest.TestCase):
    """Guard 4: `map #<id>` may be described in comments, never executed.

    Scanning string literals rather than raw text is deliberate -- the whole
    reason this bug is documented at length in the source is so the next reader
    does not reintroduce it, and a plain grep would fail on those comments.
    """

    def test_no_python_string_literal_builds_a_map_id_command(self):
        tree = ast.parse(io.open('haproxy_manager.py', encoding='utf-8').read())
        offenders = [
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and MAP_BY_ID_RE.search(node.value)
            and not (ast.get_docstring(tree) == node.value)
        ]
        # Docstrings are string literals too; exclude any literal that is a
        # docstring of a module/class/function.
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc:
                    docstrings.add(doc)
        offenders = [o for o in offenders if o not in docstrings]
        self.assertEqual(offenders, [],
                         'these string literals build a map command with an '
                         'unstable #<id> reference')

    def test_no_shell_or_template_code_line_uses_a_map_id(self):
        targets = (glob.glob('scripts/*.sh') + glob.glob('templates/*.tpl')
                   + ['Dockerfile'])
        offenders = []
        for path in targets:
            if not os.path.exists(path):
                continue
            for lineno, line in enumerate(
                    io.open(path, encoding='utf-8').read().splitlines(), 1):
                if line.lstrip().startswith('#'):
                    continue  # a comment describing the old form is fine
                if MAP_BY_ID_RE.search(line):
                    offenders.append('%s:%d: %s' % (path, lineno, line.strip()))
        self.assertEqual(offenders, [],
                         'map ids are assigned at config-parse time and move; '
                         'reference the map file by path')


if __name__ == '__main__':
    unittest.main(verbosity=2)
