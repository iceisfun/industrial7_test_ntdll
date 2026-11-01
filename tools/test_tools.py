#!/usr/bin/env python3
"""Regression tests for source inventory and log aggregation (no Windows needed)."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('corpus_coverage', HERE / 'coverage.py')
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


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


if __name__ == '__main__':
    unittest.main()
