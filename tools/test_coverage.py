#!/usr/bin/env python3
"""Additional literal/pinned-resolution inventory regressions."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import json
import subprocess
import sys

spec = importlib.util.spec_from_file_location('corpus_coverage', Path(__file__).with_name('coverage.py'))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class CoverageTests(unittest.TestCase):
    def test_failed_checks_are_not_incomplete_execution(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            (root / 'a.txt').write_text('SUMMARY tests=2 failed=1 skipped=0 checks_pass=3 checks_fail=1\n')
            (root / 'run.json').write_text(json.dumps([dict(area='a', exit_code=1, completed=True, timeout=False)]))
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('summarize.py')), str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('incomplete=0', result.stdout)
            self.assertIn('RUN FAILED CHECKS (completed)', result.stdout)

    def test_preprocessed_casts_and_pointer_calls(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'tests').mkdir()
            (root / 'tools/ntdll_exports.txt').write_text('RtlA\nRtlB\nRtlC\n')
            (root / 'tests/a.c').write_text('/* macro-driven source */')
            expanded = '''
                void a(void) { CHECK(((pfn)t_proc("RtlA"))(1)); }
                void b(void) { pfn f = ((pfn)t_proc_in("ntdll.dll", "RtlB")); CHECK(f(1)); }
                void c(void) { if (!((pfn)t_proc("RtlC"))) return; }
            '''
            with mock.patch.object(coverage, 'preprocessed_test_source', return_value=expanded):
                result = coverage.inventory(root, preprocess=True)
            self.assertEqual(set(result['calls']), {'RtlA', 'RtlB'})
            self.assertIn('RtlC', result['resolutions'])
            self.assertTrue(result['preprocessed'])

    def test_strings_do_not_invent_calls(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'tests').mkdir()
            (root / 'tools/ntdll_exports.txt').write_text('RtlA\nRtlB\nRtlC\nRtlD\n')
            (root / 'tests/a.c').write_text('''
                puts("U(RtlA)(not_a_call)");
                fn = UN(RtlB); puts("fn(not_a_call)");
                UIN("ntdll.dll", RtlC)(1);
                actual = (custom_pfn)t_proc_in("ntdll.dll", "RtlD");
                CHECK(actual(2));
            ''')
            result = coverage.inventory(root)
            self.assertEqual(set(result['calls']), {'RtlC', 'RtlD'})
            self.assertEqual(set(result['resolutions']), {'RtlB', 'RtlC', 'RtlD'})


if __name__ == '__main__':
    unittest.main()
