#!/usr/bin/env python3
"""Additional literal/pinned-resolution inventory regressions."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('corpus_coverage', Path(__file__).with_name('coverage.py'))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class CoverageTests(unittest.TestCase):
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
