#!/usr/bin/env python3
"""Regression tests for WAF request-body inspection (Coraza via SPOE).

Why this file exists
--------------------
Measured 2026-10-09 on haproxy 3.0.11 + coraza-spoa v0.7.1 + CRS 4.25.0
(report: waf-body-hardening-report.md):

  * Without `option http-buffer-request`, send-spoe-group fires at header
    time and `req.body` holds only what happened to arrive with the headers.
    A 14-byte `content=$a($b)` POST (CRS 933180, an ENFORCED rule) passed
    uninspected when its body was written in a second send(); a body sent 2s
    late, or after `Expect: 100-continue`, was never inspected at all.
  * Coraza+CRS costs ~3.3 ms per KB of body. The SPOE `timeout processing`
    is 100 ms and FAILS OPEN, so raising tune.bufsize to 32 KB turned a
    payload at byte 0 of a 30 KB base64 body into a bypass. bufsize is a
    security limit, not a performance knob.
  * coraza-spoa's SPOP library refuses frames > 65535 bytes, and Coraza's
    SecRequestBodyLimitAction Reject 413s even under DetectionOnly, so the
    three limits must stay ordered.
  * The X-WHP-WAF-Body stamp drives enforcement of body-parse errors
    (200002/200003) in WHP's generated Coraza rules. A client must never be
    able to set it, and a backend must never see it.

These tests pin the rendered config. That HAProxy ACCEPTS it is
validate-rendered-config.py's job; that it BEHAVES is the live measurement.

Running
-------
    python3 scripts/test-waf-body-inspection.py
"""

import logging
import os
import re
import sys
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

SPOA_FRAME_CAP = 65535          # dropmorepackets/haproxy-go v0.0.8 maxFrameSize
CORAZA_CONFIG = os.path.join(MODULE_DIR, 'coraza-spoa', 'config.yaml')


def render(template, coraza):
    kw = dict(crt_path='/etc/haproxy/certs', suspension_enabled=False,
              coraza_spoe_backend='coraza-spoa:9000' if coraza else None,
              cluster_secret=None, syslog_target='172.18.0.1:514')
    return haproxy_manager.template_env.get_template(template).render(**kw)


def active_lines(text):
    """Config lines with comments and blanks stripped (comments mention the
    directives by name, so a raw substring check would pass on prose)."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith('#'):
            out.append(s)
    return out


def index_of(lines, pattern):
    for i, line in enumerate(lines):
        if re.search(pattern, line):
            return i
    return -1


class ListenerWithCoraza(unittest.TestCase):

    def setUp(self):
        self.lines = active_lines(render('hap_listener.tpl', coraza=True))

    def test_body_is_buffered_before_inspection(self):
        self.assertIn('option http-buffer-request', self.lines)

    def test_stamp_order_strip_set_inspect_strip(self):
        strip1 = index_of(self.lines, r'^http-request del-header X-WHP-WAF-Body$')
        size = index_of(self.lines, r'^http-request set-var\(txn\.waf_body_size\) req\.body_size if \{ req\.hdr_cnt\(content-length\) eq 1 \}$')
        complete = index_of(self.lines, r'^http-request set-var\(txn\.waf_body\) str\(complete\) if \{ var\(txn\.waf_body_size\) -m found \} \{ req\.body_len,sub\(txn\.waf_body_size\) eq 0 \}$')
        partial = index_of(self.lines, r'^http-request set-var\(txn\.waf_body\) str\(partial\) if \{ var\(txn\.waf_body_size\) -m found \} !\{ req\.body_len,sub\(txn\.waf_body_size\) eq 0 \}$')
        hdrs_len = index_of(self.lines, r'^http-request set-var\(txn\.waf_hdrs_len\) req\.hdrs,length if !\{ var\(txn\.waf_body_size\) -m found \} \{ req\.body_len gt 0 \}$')
        nocl_complete = index_of(self.lines, r'^http-request set-var\(txn\.waf_body\) str\(complete\) if \{ var\(txn\.waf_hdrs_len\) -m found \} \{ req\.body_len,add\(txn\.waf_hdrs_len\) lt (\d+) \}$')
        nocl_partial = index_of(self.lines, r'^http-request set-var\(txn\.waf_body\) str\(partial\) if !\{ var\(txn\.waf_body_size\) -m found \} \{ req\.body_len gt 0 \} !\{ var\(txn\.waf_body\) -m found \}$')
        stamp = index_of(self.lines, r'^http-request set-header X-WHP-WAF-Body %\[var\(txn\.waf_body\)\] if \{ var\(txn\.waf_body\) -m found \}$')
        spoe = index_of(self.lines, r'^http-request send-spoe-group coraza coraza-req$')
        deny = index_of(self.lines, r'^http-request return status 403 .*var\(txn\.coraza\.action\) -m str deny')
        dup_ct = index_of(self.lines, r'^http-request deny deny_status 400 if \{ req\.fhdr_cnt\(content-type\) gt 1 \}$')
        self.assertGreaterEqual(dup_ct, 0, 'duplicate Content-Type must be rejected at the edge')
        self.assertLess(dup_ct, spoe, 'and before Coraza is asked')
        for name, idx in (('client-copy strip', strip1), ('size var', size), ('complete', complete),
                          ('partial', partial), ('no-CL header length', hdrs_len),
                          ('no-CL complete', nocl_complete),
                          ('no-CL partial', nocl_partial), ('stamp', stamp),
                          ('send-spoe-group', spoe), ('deny', deny)):
            self.assertGreaterEqual(idx, 0, f'{name} rule missing from the rendered listener')
        # Client copies stripped BEFORE we stamp, stamp BEFORE the SPOE call.
        self.assertLess(strip1, size)
        self.assertLess(size, complete)
        # The no-CL `partial` fallback relies on "-m found" of an earlier
        # `complete`: order is load-bearing.
        self.assertLess(size, hdrs_len)
        self.assertLess(hdrs_len, nocl_complete)
        self.assertLess(nocl_complete, nocl_partial)
        self.assertLess(max(complete, partial, nocl_partial), stamp)
        self.assertLess(stamp, spoe)
        # Stripped again AFTER the SPOE call so no backend ever sees it.
        strip2 = [i for i, l in enumerate(self.lines)
                  if l == 'http-request del-header X-WHP-WAF-Body' and i > spoe]
        self.assertTrue(strip2, 'X-WHP-WAF-Body must be deleted again after send-spoe-group')
        self.assertLess(strip2[0], deny)

    def test_no_content_length_complete_cannot_have_filled_the_buffer(self):
        """Without a Content-Length, `complete` is inferred from "the buffer
        cannot have been full". body + headers thresholds must sit well below
        bufsize - maxrewrite (1024), or a truncated chunked body would be
        stamped complete and a parse error on it would 403."""
        line = [l for l in self.lines if 'str(complete) if { var(txn.waf_hdrs_len)' in l][0]
        total_lt = int(re.search(r'add\(txn\.waf_hdrs_len\) lt (\d+)', line).group(1))
        header = active_lines(render('hap_header.tpl', coraza=True))
        bufsize = int([l for l in header if l.startswith('tune.bufsize')][0].split()[1])
        self.assertLessEqual(total_lt, (bufsize - 1024) * 0.85)

    def test_complete_and_partial_are_mutually_exclusive_conditions(self):
        """With a Content-Length, `complete` and `partial` must be the same
        condition, negated -- an inverted or loosened `complete` would enforce
        parse errors on truncated bodies (403 on large legitimate posts)."""
        c = [l for l in self.lines if 'str(complete) if { var(txn.waf_body_size)' in l]
        p = [l for l in self.lines if 'str(partial) if { var(txn.waf_body_size)' in l]
        self.assertEqual((len(c), len(p)), (1, 1))
        c, p = c[0], p[0]
        self.assertEqual(c.split(' if ', 1)[1].replace('!{', '{'),
                         p.split(' if ', 1)[1].replace('!{', '{'))
        self.assertIn('!{ req.body_len', p)
        self.assertNotIn('!{', c)

    def test_stamp_never_set_from_client_input(self):
        """The only set-header for the stamp is from our own var."""
        sets = [l for l in self.lines if re.search(r'set-header\s+X-WHP-WAF-Body', l, re.I)]
        self.assertEqual(len(sets), 1)
        self.assertIn('%[var(txn.waf_body)]', sets[0])
        self.assertFalse([l for l in self.lines if re.search(r'add-header\s+X-WHP-WAF-Body', l, re.I)])

    def test_access_log_carries_coverage_fields(self):
        lf = [l for l in self.lines if l.startswith('log-format ')]
        self.assertEqual(len(lf), 1)
        self.assertTrue(lf[0].endswith('wafb=%[var(txn.waf_body)] wafe=%[var(txn.coraza.error)]"'))

    def test_fail_open_preserved(self):
        """Nothing may deny on var(txn.coraza.error): an SPOA outage must not
        503 customer sites."""
        self.assertFalse([l for l in self.lines if 'txn.coraza.error' in l and
                          re.search(r'\b(deny|reject|return|silent-drop|tarpit)\b', l)])


class ListenerWithoutCoraza(unittest.TestCase):

    def test_waf_off_config_has_no_body_buffering(self):
        lines = active_lines(render('hap_listener.tpl', coraza=False))
        self.assertNotIn('option http-buffer-request', lines)
        self.assertFalse([l for l in lines if 'X-WHP-WAF-Body' in l])
        self.assertFalse([l for l in lines if 'send-spoe-group' in l])

    def test_waf_off_header_keeps_default_bufsize(self):
        lines = active_lines(render('hap_header.tpl', coraza=False))
        self.assertFalse([l for l in lines if l.startswith('tune.bufsize')])


class BufsizeCeilings(unittest.TestCase):

    def setUp(self):
        lines = active_lines(render('hap_header.tpl', coraza=True))
        found = [l for l in lines if l.startswith('tune.bufsize')]
        self.assertEqual(len(found), 1, 'tune.bufsize must be pinned when Coraza is on')
        self.bufsize = int(found[0].split()[1])
        spoe = active_lines(haproxy_manager.template_env.get_template(
            'hap_coraza_spoe_engine.tpl').render())
        m = [re.match(r'timeout\s+processing\s+(\d+)ms$', l) for l in spoe]
        m = [x for x in m if x]
        self.assertEqual(len(m), 1)
        self.processing_ms = int(m[0].group(1))

    def test_bufsize_fits_the_spoe_time_budget(self):
        """~3.3 ms/KB measured; 31 KB took 104 ms against a 100 ms timeout and
        FAILED OPEN. Keep the worst case at about half the budget."""
        worst_ms = (self.bufsize / 1024.0) * 3.3
        self.assertLessEqual(worst_ms, self.processing_ms * 0.6,
                             f'tune.bufsize {self.bufsize} => ~{worst_ms:.0f} ms of Coraza time '
                             f'against a {self.processing_ms} ms fail-open timeout')

    def test_bufsize_below_spop_frame_cap(self):
        self.assertLess(self.bufsize, SPOA_FRAME_CAP)

    def test_body_arg_is_the_full_buffered_body(self):
        """The message must keep sending req.body unsliced: the `complete`
        stamp compares req.body_len to Content-Length, so a slice would make
        a truncated body look complete to Coraza."""
        spoe = haproxy_manager.template_env.get_template('hap_coraza_spoe_engine.tpl').render()
        args = [l.strip() for l in spoe.splitlines() if l.strip().startswith('args ')]
        self.assertEqual(len(args), 1)
        self.assertTrue(args[0].endswith(' body=req.body'))


CORAZA_OVERRIDES = os.path.join(MODULE_DIR, 'coraza-spoa', 'overrides.conf')


@unittest.skipUnless(os.path.exists(CORAZA_OVERRIDES),
                     'coraza-spoa/overrides.conf is not shipped in this image; '
                     'this class runs from a repo checkout')
class BakedPromotions(unittest.TestCase):
    """920440 is a CHAIN whose first link matches every URL with a file
    extension. `SecRuleUpdateActionById 920440 "ctl:ruleEngine=On"` ran on that
    first link, so every *.php / *.css request was evaluated with the engine
    On (full CRS anomaly enforcement, in detect_only mode too). Measured
    in-process and live, 2026-10-09; fixed by keying the flip on the chain's
    real condition."""

    def setUp(self):
        with open(CORAZA_OVERRIDES) as fh:
            self.lines = active_lines(fh.read())

    def test_920440_is_not_promoted_on_its_chain_starter(self):
        self.assertFalse([l for l in self.lines
                          if re.match(r'SecRuleUpdateActionById\s+(\S*-)?920440\b', l)],
                         '920440 promoted via SecRuleUpdateActionById again')

    def test_920440_flip_keys_on_the_restricted_extension(self):
        i = self.lines.index('SecRule TX:EXTENSION "@within %{tx.restricted_extensions}" \\')
        self.assertEqual(self.lines[i + 1],
                         '"id:992920440,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleEngine=On"')


@unittest.skipUnless(os.path.exists(CORAZA_CONFIG),
                     'coraza-spoa/config.yaml is not shipped in this image; '
                     'this class runs from a repo checkout')
class CorazaBodyLimits(unittest.TestCase):

    def setUp(self):
        with open(CORAZA_CONFIG) as fh:
            self.cfg = active_lines(fh.read())
        header = active_lines(render('hap_header.tpl', coraza=True))
        self.bufsize = int([l for l in header if l.startswith('tune.bufsize')][0].split()[1])

    def directive(self, name):
        vals = [l.split(None, 1)[1] for l in self.cfg if l.split()[0] == name]
        self.assertEqual(len(vals), 1, f'{name} must be set exactly once in config.yaml')
        return vals[0]

    def test_limit_strictly_above_anything_haproxy_can_send(self):
        limit = int(self.directive('SecRequestBodyLimit'))
        self.assertGreater(limit, SPOA_FRAME_CAP)
        self.assertGreater(limit, self.bufsize)

    def test_over_limit_never_rejects(self):
        """Reject interrupts even under DetectionOnly -> 403 on uploads."""
        self.assertEqual(self.directive('SecRequestBodyLimitAction'), 'ProcessPartial')

    def test_body_buffer_stays_in_memory(self):
        self.assertGreaterEqual(int(self.directive('SecRequestBodyInMemoryLimit')),
                                int(self.directive('SecRequestBodyLimit')))

    def test_json_depth_limit_pinned(self):
        """Quadratic JSON flattening: depth 300 = 297 ms, past the fail-open
        timeout. Legitimate WordPress JSON measured at depth <= 9."""
        depth = int(self.directive('SecRequestBodyJsonDepthLimit'))
        self.assertGreaterEqual(depth, 32, 'too tight for real block/theme payloads')
        self.assertLessEqual(depth, 64, 'depth 100 already costs ~40 ms')

    def test_limits_are_set_after_the_recommended_file(self):
        inc = self.cfg.index('Include @coraza.conf-recommended')
        for name in ('SecRequestBodyLimit ', 'SecRequestBodyJsonDepthLimit '):
            lim = [i for i, l in enumerate(self.cfg) if l.startswith(name)][0]
            self.assertLess(inc, lim, f'the recommended file would override {name.strip()}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
