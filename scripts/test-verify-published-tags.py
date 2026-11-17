#!/usr/bin/env python3
"""Offline tests for scripts/verify-published-tags.sh (final publish gate).

CI run 5381 failed because buildx v0.28.0 ignores `--format '{{.Manifest.Digest}}'`
and prints the whole inspect text, while buildx 0.38 prints a bare digest. A stub
`imagetools` emulates BOTH output styles (plus `--raw`), so no registry or Docker
is needed. Held invariants:
  - the 0.28-style (full text) and 0.38-style (bare digest) outputs both verify
  - a reported digest that disagrees with the sha256 of the raw manifest fails
  - a missing tag, a platform mismatch, or different digests across registries /
    tags fail the job
  - build-push.yaml's verify step uses the script, and release/* + rc-* tags
    resolve to ONLY <version>-rc and <sha> (never latest)

Running:  python3 scripts/test-verify-published-tags.py   (needs jq)
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(HERE, 'verify-published-tags.sh')
WORKFLOW = os.path.join(ROOT, '.gitea', 'workflows', 'build-push.yaml')

STUB = r'''#!/usr/bin/env python3
import hashlib, json, os, sys
a = sys.argv[1:]
mode = os.environ['STUB_MODE']            # v028 | v038
table = json.load(open(os.environ['STUB_TABLE']))   # ref -> {"raw": str, "lie": optional digest}
assert a[0] == 'inspect'
ref = [x for x in a[1:] if not x.startswith('-') and not x.startswith('{{')][0]
ent = table.get(ref)
if ent is None:
    sys.stderr.write('ERROR: %s: not found\n' % ref); sys.exit(1)
raw = ent['raw'].encode() + (b'\n' if ent.get('nl') else b'')
digest = ent.get('lie') or 'sha256:' + hashlib.sha256(ent['raw'].encode()).hexdigest()
if '--raw' in a:
    sys.stdout.buffer.write(raw); sys.exit(0)
if '--format' in a:
    if mode == 'v038':
        print(digest)
    else:   # 0.28: --format ignored, whole text printed
        print('Name:      ' + ref); print('MediaType: application/vnd.oci.image.index.v1+json')
        print('Digest:    ' + digest)
    sys.exit(0)
print('Name:      ' + ref)
print('MediaType: application/vnd.oci.image.index.v1+json')
print('Digest:    ' + digest)
print('           ')
print('Manifests: ')
for m in json.loads(ent['raw'])['manifests']:
    print('  Name:        %s@%s' % (ref, m['digest']))
    print('  Digest:      sha256:' + 'f' * 64)   # indented: must never be mistaken for the index digest
    print('  Platform:    %s/%s' % (m['platform']['os'], m['platform']['architecture']))
'''


def index(archs, salt=''):
    ms = [{'mediaType': 'application/vnd.oci.image.manifest.v1+json',
           'digest': 'sha256:' + hashlib.sha256((x + salt).encode()).hexdigest(), 'size': 1,
           'platform': {'architecture': x, 'os': 'linux'}} for x in archs]
    ms.append({'mediaType': 'application/vnd.oci.image.manifest.v1+json',
               'digest': 'sha256:' + '7' * 64, 'size': 1,
               'platform': {'architecture': 'unknown', 'os': 'unknown'},
               'annotations': {'vnd.docker.reference.type': 'attestation-manifest'}})
    return json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                       'manifests': ms}, separators=(',', ':'))


REPOS = ['reg.one/a/img', 'reg.two/b/img']
TAGS = ['1.2-rc', 'abc123']


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stub = os.path.join(self.tmp.name, 'stub')
        open(self.stub, 'w').write(STUB)
        os.chmod(self.stub, os.stat(self.stub).st_mode | stat.S_IEXEC)
        self.table = os.path.join(self.tmp.name, 'table.json')

    def tearDown(self):
        self.tmp.cleanup()

    def table_for(self, raw, **over):
        t = {'%s:%s' % (r, g): {'raw': raw} for r in REPOS for g in TAGS}
        for k, v in over.items():
            ref = k.replace('__', ':').replace('_', '/', 0)
            t[ref] = v
        return t

    def run_script(self, table, mode, platforms='linux/amd64,linux/arm64', tags=TAGS):
        json.dump(table, open(self.table, 'w'))
        args = [SCRIPT, '--platforms', platforms]
        for r in REPOS:
            args += ['--repo', r]
        for t in tags:
            args += ['--tag', t]
        env = dict(os.environ, IMAGETOOLS=self.stub, STUB_MODE=mode, STUB_TABLE=self.table)
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)

    def test_buildx_028_full_text_output_verifies(self):
        r = self.run_script(self.table_for(index(['amd64', 'arm64'])), 'v028')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('verified:', r.stdout)
        self.assertNotIn('bad digest', r.stdout)

    def test_buildx_038_bare_digest_output_verifies(self):
        r = self.run_script(self.table_for(index(['amd64', 'arm64'])), 'v038')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_trailing_newline_on_raw_output_tolerated(self):
        raw = index(['amd64', 'arm64'])
        t = {'%s:%s' % (r, g): {'raw': raw, 'nl': True} for r in REPOS for g in TAGS}
        self.assertEqual(self.run_script(t, 'v028').returncode, 0)

    def test_amd64_only_publish_matches_platforms(self):
        raw = index(['amd64'])
        self.assertEqual(self.run_script(self.table_for(raw), 'v028', 'linux/amd64').returncode, 0)
        r = self.run_script(self.table_for(raw), 'v028', 'linux/amd64,linux/arm64')
        self.assertEqual(r.returncode, 1)
        self.assertIn('platform mismatch', r.stdout)

    def test_missing_tag_fails(self):
        t = self.table_for(index(['amd64', 'arm64']))
        del t['reg.two/b/img:abc123']
        r = self.run_script(t, 'v038')
        self.assertEqual(r.returncode, 1)
        self.assertIn('MISSING', r.stdout)

    def test_different_digest_across_registries_fails(self):
        t = self.table_for(index(['amd64', 'arm64']))
        t['reg.two/b/img:1.2-rc'] = {'raw': index(['amd64', 'arm64'], salt='other')}
        for mode in ('v028', 'v038'):
            r = self.run_script(t, mode)
            self.assertEqual(r.returncode, 1, mode)
            self.assertIn('digest mismatch', r.stdout)

    def test_reported_digest_disagreeing_with_raw_manifest_fails(self):
        t = self.table_for(index(['amd64', 'arm64']))
        t['reg.one/a/img:1.2-rc']['lie'] = 'sha256:' + '0' * 64
        for mode in ('v028', 'v038'):
            r = self.run_script(t, mode)
            self.assertEqual(r.returncode, 1, mode)
            self.assertIn('cross-check FAILED', r.stdout)

    def test_garbage_manifest_fails(self):
        t = self.table_for('not json')
        self.assertEqual(self.run_script(t, 'v038').returncode, 1)


class WorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yaml
        cls.src = open(WORKFLOW).read()
        cls.doc = yaml.safe_load(cls.src)
        cls.steps = cls.doc['jobs']['Build-and-Push']['steps']

    def step(self, name):
        return [s for s in self.steps if s.get('name') == name][0]

    def test_verify_step_uses_script_not_format_digest(self):
        run = self.step('Verify published tags in every registry')['run']
        self.assertIn('scripts/verify-published-tags.sh', run)
        self.assertNotIn('{{.Manifest.Digest}}', run)

    def test_run_blocks_are_valid_bash(self):
        for s in self.steps:
            if 'run' in s:
                p = subprocess.run(['bash', '-n'], input=s['run'], text=True, capture_output=True)
                self.assertEqual(p.returncode, 0, '%s: %s' % (s.get('name'), p.stderr))

    def test_release_and_rc_never_publish_latest(self):
        run = self.step('Resolve tags')['run']
        m = re.search(r'refs/heads/release/\*\|refs/tags/rc-\*\)\s*\n\s*tags="([^"]*)"', run)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), '${VERSION}-rc ${SHA}')
        main = re.search(r'refs/heads/main\)\s*\n\s*tags="([^"]*)"', run)
        self.assertIsNotNone(main)
        self.assertEqual(main.group(1), 'latest ${VERSION} ${SHA}')
        # latest appears in no other tag assignment
        self.assertEqual(len(re.findall(r'tags="[^"]*latest', run)), 1)


if __name__ == '__main__':
    unittest.main()
