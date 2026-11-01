#!/usr/bin/env python3
"""Regression tests for source inventory and log aggregation (no Windows needed)."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('corpus_coverage', HERE / 'coverage.py')
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)
spec = importlib.util.spec_from_file_location('smoke_all', HERE / 'smoke_all.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class ToolsTests(unittest.TestCase):
    def test_resolution_is_not_invocation(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'tests').mkdir()
            (root / 'tools/ntdll_exports.txt').write_text('RtlA\nRtlB\nRtlC\nRtlD\nRtlE\n')
            (root / 'tests/example.c').write_text('''
                REQUIRE(U(RtlA));
                // U(RtlD)(bad);
                /* U(RtlE)(bad); */
                U(RtlB)(1);
                fn = UN(RtlC);
                CHECK(fn(2));
            ''')
            result = coverage.inventory(root)
            self.assertEqual(set(result['calls']), {'RtlB', 'RtlC'})
            self.assertIn('RtlA', result['resolutions'])
            self.assertEqual(result['not_invoked'], ['RtlA', 'RtlD', 'RtlE'])

    def summarize(self, logs):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            for name, content in logs.items():
                (Path(directory) / name).write_text(content)
            return subprocess.run([sys.executable, str(HERE / 'summarize.py'), directory], capture_output=True, text=True)

    def test_clean_summary_and_stderr(self):
        result = self.summarize({'a.txt': 'SUMMARY tests=2 failed=0 skipped=1 checks_pass=4 checks_fail=0\n', 'a.stderr.txt': 'Wine warning\n'})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('TOTAL tests=2', result.stdout)

    def test_missing_summary_fails(self):
        self.assertEqual(self.summarize({'a.txt': 'RUN a\n'}).returncode, 1)

    def test_duplicate_summary_fails(self):
        line = 'SUMMARY tests=1 failed=0 skipped=0 checks_pass=1 checks_fail=0\n'
        self.assertEqual(self.summarize({'a.txt': line * 2}).returncode, 1)

    def test_failed_checks_fail(self):
        self.assertEqual(self.summarize({'a.txt': 'SUMMARY tests=1 failed=1 skipped=0 checks_pass=0 checks_fail=1\n'}).returncode, 1)

    def test_no_logs_fails(self):
        self.assertEqual(self.summarize({}).returncode, 1)

    def test_malformed_second_summary_fails(self):
        line = 'SUMMARY tests=1 failed=0 skipped=0 checks_pass=1 checks_fail=0\n'
        self.assertEqual(self.summarize({'a.txt': line + 'SUMMARY truncated\n'}).returncode, 1)

    def test_invalid_counts_fail(self):
        for tests, skipped in [(0, 0), (1, 2)]:
            with self.subTest(tests=tests, skipped=skipped):
                self.assertEqual(self.summarize({'a.txt': 'SUMMARY tests=%d failed=0 skipped=%d checks_pass=0 checks_fail=0\n' % (tests, skipped)}).returncode, 1)

    def test_runner_metadata_overrides_clean_summary(self):
        line = 'SUMMARY tests=1 failed=0 skipped=0 checks_pass=1 checks_fail=0\n'
        for row in [dict(area='a', exit_code=1, completed=True, timeout=False),
                    dict(area='a', exit_code=124, timeout=True),
                    dict(area='a', exitCode=0, timeout=True, ok=False),
                    dict(area='missing', exitCode=0, timeout=False, ok=True)]:
            with self.subTest(row=row):
                self.assertEqual(self.summarize({'a.txt': line, 'run.json': json.dumps([row])}).returncode, 1)
        row = dict(area='a', exitCode=0, timeout=False, ok=True)
        self.assertEqual(self.summarize({'a.txt': line, 'run.json': '\ufeff' + json.dumps([row])}).returncode, 0)

    def test_invalid_runner_metadata_fails(self):
        for text in ['broken', '{}', '[]', '[null]']:
            self.assertEqual(self.summarize({'run.json': text}).returncode, 1)

    def test_smoke_rejects_failed_exit_and_checks(self):
        clean = dict(completed=True, exit_code=0, failed=0, checks_fail=0)
        self.assertFalse(smoke.row_failed(clean))
        for change in [dict(exit_code=1), dict(checks_fail=1), dict(completed=False)]:
            self.assertTrue(smoke.row_failed(dict(clean, **change)))

    def test_smoke_main_rejects_exit_one_after_clean_summary(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            (root / 'build').mkdir()
            (root / 'tools').mkdir()
            (root / 'build/a.exe').touch()
            runner = root / 'tools/wine_run.sh'
            runner.write_text('#!/bin/sh\necho "SUMMARY tests=1 failed=0 skipped=0 checks_pass=1 checks_fail=0"\nexit 1\n')
            runner.chmod(0o755)
            with mock.patch.object(smoke, '__file__', str(root / 'tools/smoke_all.py')), \
                    mock.patch.object(sys, 'argv', ['smoke_all.py', '--results', str(root / 'results')]), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(smoke.main(), 1)
            self.assertEqual(json.loads((root / 'results/run.json').read_text())[0]['exit_code'], 1)
            runner.unlink()
            (root / 'results/run.json').write_text('[{"area":"a","exit_code":0}]')
            with mock.patch.object(smoke, '__file__', str(root / 'tools/smoke_all.py')), \
                    mock.patch.object(sys, 'argv', ['smoke_all.py', '--results', str(root / 'results')]), \
                    self.assertRaises(FileNotFoundError):
                smoke.main()
            self.assertEqual(json.loads((root / 'results/run.json').read_text()), [])

    def test_outer_timeout_kills_group_even_if_wrapper_exits_on_term(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            pidfile = Path(directory) / 'child.pid'
            code = '''import os, signal, sys, time
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True: time.sleep(1)
open(sys.argv[1], 'w').write(str(pid))
while True: time.sleep(1)
'''
            with open(os.devnull, 'w') as stream:
                result = smoke.run_command([sys.executable, '-c', code, str(pidfile)],
                                           cwd=directory, env=os.environ, stream=stream,
                                           timeout=0.5, grace=0.5)
            self.assertEqual(result, (124, True))
            pid = int(pidfile.read_text())
            # An orphan can remain a zombie until init reaps it, but cannot run.
            stat = Path('/proc/%d/stat' % pid)
            for _ in range(100):
                if not stat.exists() or stat.read_text().split()[2] == 'Z':
                    break
                time.sleep(0.01)
            if stat.exists():
                self.assertEqual(stat.read_text().split()[2], 'Z')

    def test_wrapper_hard_timeout_and_cleanup(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            (root / 'base/drive_c').mkdir(parents=True)
            wine = root / 'wine'
            wine.write_text('#!/bin/sh\ntrap "" TERM\nwhile :; do sleep 1; done\n')
            wine.chmod(0o755)
            server = root / 'wineserver'
            server.write_text('#!/bin/sh\nexit 0\n')
            server.chmod(0o755)
            env = dict(os.environ, WINE=str(wine), TP_BASE_PREFIX=str(root / 'base'),
                       TP_TIMEOUT='0.1', TMPDIR=directory, TP_DISPLAY='none')
            result = subprocess.run([str(HERE / 'wine_run.sh'), 'unused.exe'], env=env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 137, result.stderr)
            self.assertEqual(list(root.glob('tp_prefix.*')), [])


if __name__ == '__main__':
    unittest.main()
