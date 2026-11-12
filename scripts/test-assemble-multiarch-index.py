#!/usr/bin/env python3
"""Offline tests for scripts/assemble-multiarch-index.sh (multi-arch index assembly).

The script is the publish-side half of the multi-arch pipeline: it receives the
amd64 and (optional) arm64 digests that the build steps pushed BY DIGEST and
turns them into the tag(s). A stub stands in for `docker buildx imagetools`
(env IMAGETOOLS), records every `create` call and answers `inspect` from a
table, so no registry or Docker is needed.

Held invariants:
  - arm64 failure / cancel / skip  -> amd64-only create, exit 0 (tag still published)
  - a STALE arm64 digest is never attached unless this run's arm64 outcome is success
  - bad/missing amd64 digest, or amd64 that is not linux/amd64 -> exit 1, NO create
  - an arm64 digest that does not inspect as arm64 is dropped (amd64-only)
  - every tag x every repo is created; sources are <repo>@<digest> in that repo

Running:  python3 scripts/test-assemble-multiarch-index.py
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'assemble-multiarch-index.sh')
A = 'sha256:' + 'a' * 64
B = 'sha256:' + 'b' * 64
C = 'sha256:' + 'c' * 64

STUB = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
log = os.environ['STUB_LOG']
table = json.loads(os.environ['STUB_ARCH'])
if a[0] == 'inspect':
    ref = [x for x in a[1:] if '@sha256:' in x][0]
    arch = table.get(ref.split('@', 1)[1])
    if arch is None:
        sys.exit(1)
    print(json.dumps({'architecture': arch, 'os': 'linux'}))
elif a[0] == 'create':
    open(log, 'a').write(json.dumps(a[1:]) + '\n')
else:
    sys.exit(2)
'''


class AssembleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stub = os.path.join(self.tmp.name, 'stub')
        with open(self.stub, 'w') as f:
            f.write(STUB)
        os.chmod(self.stub, os.stat(self.stub).st_mode | stat.S_IEXEC)
        self.log = os.path.join(self.tmp.name, 'creates.log')

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, args, arch=None):
        env = dict(os.environ, IMAGETOOLS=self.stub, STUB_LOG=self.log,
                   STUB_ARCH=json.dumps(arch if arch is not None else {A: 'amd64', B: 'arm64'}))
        p = subprocess.run(['bash', SCRIPT] + args, env=env, capture_output=True, text=True)
        creates = []
        if os.path.exists(self.log):
            creates = [json.loads(l) for l in open(self.log)]
        return p, creates

    BASE = ['--repo', 'r.example/o/img', '--tag', 'latest']

    def test_both_platforms(self):
        p, c = self.run_script(['--amd64', A, '--arm64', B, '--arm64-outcome', 'success'] + self.BASE)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(c, [['-t', 'r.example/o/img:latest', 'r.example/o/img@' + A, 'r.example/o/img@' + B]])
        self.assertIn('platforms=linux/amd64,linux/arm64', p.stdout)

    def test_arm64_failure_is_amd64_only_even_with_a_digest(self):
        # A stale digest (e.g. left over from an earlier run) must not be attached.
        for outcome in ('failure', 'cancelled', 'skipped', ''):
            if os.path.exists(self.log):
                os.remove(self.log)
            p, c = self.run_script(['--amd64', A, '--arm64', B, '--arm64-outcome', outcome] + self.BASE)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(c, [['-t', 'r.example/o/img:latest', 'r.example/o/img@' + A]], outcome)
            self.assertIn('::warning::', p.stdout)
            self.assertIn('platforms=linux/amd64\n', p.stdout)

    def test_no_arm64_args_is_amd64_only(self):
        p, c = self.run_script(['--amd64', A] + self.BASE)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(c, [['-t', 'r.example/o/img:latest', 'r.example/o/img@' + A]])

    def test_success_with_empty_or_malformed_arm64_digest(self):
        for bad in ('', 'sha256:short', 'latest'):
            if os.path.exists(self.log):
                os.remove(self.log)
            p, c = self.run_script(['--amd64', A, '--arm64', bad, '--arm64-outcome', 'success'] + self.BASE)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(len(c[0]), 3, bad)  # -t, ref, one source

    def test_arm64_digest_that_is_not_arm64_is_dropped(self):
        p, c = self.run_script(['--amd64', A, '--arm64', C, '--arm64-outcome', 'success'] + self.BASE,
                               arch={A: 'amd64', C: 'amd64'})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(c, [['-t', 'r.example/o/img:latest', 'r.example/o/img@' + A]])

    def test_arm64_equal_to_amd64_is_dropped(self):
        p, c = self.run_script(['--amd64', A, '--arm64', A, '--arm64-outcome', 'success'] + self.BASE)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(c[0]), 3)

    def test_amd64_problems_publish_nothing(self):
        for amd in ('', 'nope', B):  # B inspects as arm64
            p, c = self.run_script(['--amd64', amd, '--arm64', B, '--arm64-outcome', 'success'] + self.BASE)
            self.assertNotEqual(p.returncode, 0, amd)
            self.assertEqual(c, [], amd)
        p, c = self.run_script(['--amd64', C, '--arm64-outcome', 'failure'] + self.BASE, arch={})
        self.assertNotEqual(p.returncode, 0)  # not inspectable
        self.assertEqual(c, [])

    def test_all_tags_in_all_repos(self):
        p, c = self.run_script(['--amd64', A, '--arm64', B, '--arm64-outcome', 'success',
                                '--repo', 'gitea.example/o/img', '--repo', 'ghcr.io/o/img',
                                '--tag', 'latest', '--tag', '1.2.3', '--tag', 'abc123'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(c), 2)
        self.assertEqual(c[0], ['-t', 'gitea.example/o/img:latest', '-t', 'gitea.example/o/img:1.2.3',
                                '-t', 'gitea.example/o/img:abc123',
                                'gitea.example/o/img@' + A, 'gitea.example/o/img@' + B])
        self.assertEqual(c[1][-2:], ['ghcr.io/o/img@' + A, 'ghcr.io/o/img@' + B])

    def test_requires_repo_and_tag_and_rejects_unknown_args(self):
        for args in (['--amd64', A, '--tag', 't'], ['--amd64', A, '--repo', 'r'], ['--bogus', 'x']):
            p, c = self.run_script(args)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(c, [])


class WorkflowWiring(unittest.TestCase):
    """The workflow must keep the properties the script relies on."""

    def setUp(self):
        self.wf = open(os.path.join(HERE, '..', '.gitea', 'workflows', 'build-push-coraza.yaml')).read()

    def test_arm64_step_is_non_fatal_and_digest_comes_from_step_output(self):
        self.assertIn('continue-on-error: true', self.wf)
        self.assertIn('steps.arm64.outputs.digest', self.wf)
        self.assertIn('steps.arm64.outcome', self.wf)
        self.assertIn('assemble-multiarch-index.sh', self.wf)

    def test_both_builds_push_by_digest_untagged(self):
        self.assertEqual(self.wf.count('push-by-digest=true'), 2)
        self.assertNotIn('tags:', self.wf.replace('# tags:', ''))

    def test_no_tag_is_pushed_by_a_build_step(self):
        # tags exist only via imagetools create (the assemble script)
        self.assertNotIn('ghcr.io/shadowdao/coraza-spoa:latest\n', self.wf.split('assemble-multiarch-index.sh')[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
