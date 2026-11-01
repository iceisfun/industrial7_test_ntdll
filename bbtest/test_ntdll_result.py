import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ntdll_result as nr  # noqa: E402
import pack_payload as pp  # noqa: E402

RUN3 = os.environ.get("NTDLL_RUN3_RESULTS", "run3-results")
CORPUS = os.path.dirname(RUN3)


def real(name):
    p = os.path.join(RUN3, name)
    return p if os.path.exists(p) else None


def synth(areas, extra=""):
    out = ["I7RES mode=std"]
    for a in areas:
        out += ["I7RES end %s rc=0 secs=1" % a, "I7RES begin " + a,
                "I7RES | RUN  %s_one" % a, "I7RES | OK   %s_one" % a,
                "I7RES | RUN  %s_two" % a, "I7RES |   NOTE hi",
                "I7RES | SKIP %s_two" % a,
                "I7RES | SUMMARY tests=2 failed=0 skipped=1 checks_pass=3 checks_fail=0",
                "I7RES finish " + a]
    return "\r\n".join(out) + "\r\n" + extra


class Synthetic(unittest.TestCase):
    def test_clean_run(self):
        a = ["x_a", "x_b"]
        doc, rows = nr.convert(synth(a) + "I7RES done\r\n", a)
        self.assertEqual(doc["outcome"], ["success"])
        self.assertTrue(doc["complete"])
        self.assertEqual(doc["summary"]["counts"]["total"], 4)
        self.assertEqual(doc["summary"]["counts"]["skip"], 2)
        self.assertEqual({r["case_id"] for r in rows},
                         {"x_a/x_a_one", "x_a/x_a_two", "x_b/x_b_one", "x_b/x_b_two"})

    def test_missing_area_is_not_complete(self):
        doc, _ = nr.convert(synth(["x_a"]) + "I7RES done\r\n", ["x_a", "x_b"])
        self.assertFalse(doc["complete"])
        self.assertIn("error", doc["outcome"])
        ck = {c["id"]: c for c in doc["checks"]}
        self.assertEqual(ck["ntdll.areas.complete"]["status"], "missing")
        self.assertEqual(ck["area.x_b"]["status"], "missing")
        self.assertIn({"area": "x_b", "pass": 0, "fail": 0, "missing": 1},
                      doc["summary"]["areas"])

    def test_no_done_marker(self):
        doc, _ = nr.convert(synth(["x_a"]), ["x_a"])
        self.assertFalse(doc["complete"])
        self.assertEqual({c["id"]: c["status"] for c in doc["checks"]}["i7res.done"], "missing")

    def test_fail_case_keeps_completeness_and_fails_outcome(self):
        log = ("I7RES mode=std\r\nI7RES end x rc=1 secs=1\r\nI7RES begin x\r\n"
               "I7RES | RUN  c1\r\nI7RES |   FAIL f.c:3: a == b\r\nI7RES | FAIL c1\r\n"
               "I7RES | SUMMARY tests=1 failed=1 skipped=0 checks_pass=0 checks_fail=1\r\n"
               "I7RES finish x\r\nI7RES done\r\n")
        doc, rows = nr.convert(log, ["x"])
        self.assertTrue(doc["complete"])
        self.assertEqual(doc["outcome"], ["failure"])
        self.assertEqual(rows[0]["status"], "fail")
        self.assertEqual(rows[0]["message"], "f.c:3: a == b")

    def test_timeout_area_cases_not_hidden(self):
        log = ("I7RES mode=std\r\nI7RES timeout x\r\nI7RES end x rc=TIMEOUT secs=300\r\n"
               "I7RES begin x\r\nI7RES | RUN  c1\r\nI7RES | OK   c1\r\nI7RES | RUN  c2\r\n"
               "I7RES finish x\r\nI7RES done\r\n")
        doc, rows = nr.convert(log, ["x"])
        self.assertEqual({r["name"]: r["status"] for r in rows}, {"c1": "pass", "c2": "timeout"})
        self.assertIn("timeout", doc["outcome"])
        self.assertFalse(doc["complete"])

    def test_unterminated_run_at_eof_and_fatal(self):
        log = ("I7RES begin x\r\nI7RES | RUN  c1\r\nI7RES | FATAL cannot load\r\n")
        run = nr.parse_log(log)
        self.assertEqual(run.areas["x"].cases[0]["status"], "error")
        self.assertEqual(run.areas["x"].fatal, ["cannot load"])
        self.assertFalse(run.areas["x"].complete)

    def test_duplicate_names_get_distinct_ids(self):
        log = ("I7RES begin x\r\nI7RES | RUN  c\r\nI7RES | OK   c\r\nI7RES | RUN  c\r\n"
               "I7RES | OK   c\r\nI7RES | SUMMARY tests=2 failed=0 skipped=0\r\nI7RES finish x\r\n")
        ids = [r["case_id"] for r in nr.case_rows(nr.parse_log(log))]
        self.assertEqual(ids, ["x/c", "x/c#2"])

    def test_summary_mismatch_flagged(self):
        log = ("I7RES begin x\r\nI7RES | RUN  c\r\nI7RES | OK   c\r\n"
               "I7RES | SUMMARY tests=5 failed=0 skipped=0\r\nI7RES finish x\r\nI7RES done\r\n")
        doc, _ = nr.convert(log, ["x"])
        self.assertEqual({c["id"]: c["status"] for c in doc["checks"]}["ntdll.summary.consistent"],
                         "fail")
        self.assertIn("error", doc["outcome"])

    def test_payload_exit_required(self):
        a = ["x_a"]
        ok, _ = nr.convert(synth(a) + "I7RES done\r\nI7VM: payload exit 0 \r\n", a,
                           require_payload_exit=True)
        self.assertEqual(ok["outcome"], ["success"])
        bad, _ = nr.convert(synth(a) + "I7RES done\r\nI7VM: payload exit 3 \r\n", a,
                            require_payload_exit=True)
        self.assertIn("failure", bad["outcome"])
        none, _ = nr.convert(synth(a) + "I7RES done\r\n", a, require_payload_exit=True)
        self.assertFalse(none["complete"])

    def test_env_dependent_class(self):
        doc, rows = nr.convert(synth(["x_a"]) + "I7RES done\r\n", ["x_a"], env_dependent=("x_a",))
        self.assertEqual(doc["summary"]["classes"], {"env_dependent": 2})
        self.assertTrue(all(r["class"] == "env_dependent" for r in rows))

    def test_evidence_offsets_point_at_the_line(self):
        log = synth(["x_a"]) + "I7RES done\r\n"
        doc, _ = nr.convert(log, ["x_a"])
        ev = {c["id"]: c.get("evidence") for c in doc["checks"]}
        off = int(ev["i7res.done"].split("@")[1])
        self.assertTrue(log.encode()[off:].startswith(b"I7RES done"))
        off = int(ev["area.x_a"].split("@")[1])
        self.assertTrue(log.encode()[off:].startswith(b"I7RES begin x_a"))

    def test_compare(self):
        o = {"a/c1": {"case_id": "a/c1", "area": "a", "status": "pass"},
             "a/c2": {"case_id": "a/c2", "area": "a", "status": "pass"},
             "a/c3": {"case_id": "a/c3", "area": "a", "status": "pass"}}
        i = {"a/c1": {"case_id": "a/c1", "area": "a", "status": "pass"},
             "a/c2": {"case_id": "a/c2", "area": "a", "status": "fail"}}
        rows, s = nr.compare(o, i)
        self.assertEqual((s["same"], s["diff"], s["i7_missing"]), (1, 2, 1))
        self.assertEqual(s["outcome"], ["failure", "error"])
        rows, s = nr.compare(o, i, allowed={"a/c2", "a/c3"})
        self.assertEqual((s["known"], s["diff"]), (2, 0))
        self.assertEqual(s["outcome"], ["error"])  # missing is never baselined away


@unittest.skipUnless(real("ntdll-run3b-std.serial.log"), "real run3 logs not present")
class RealLogs(unittest.TestCase):
    """Numbers are the ones summarize.py printed for the same logs."""

    def conv(self, name, **kw):
        with open(real(name), "rb") as f:
            return nr.convert(f.read(), **kw)

    def test_run3b_std(self):
        doc, rows = self.conv("ntdll-run3b-std.serial.log")
        c = doc["summary"]["counts"]
        self.assertEqual((c["total"], c["fail"], c["skip"], c["error"]), (2188, 0, 2, 0))
        self.assertEqual(len(doc["summary"]["areas"]), 34)
        self.assertTrue(doc["complete"])
        self.assertEqual(doc["outcome"], ["success"])
        self.assertEqual(doc["mode"], "std")
        self.assertEqual(doc["payload_exit"], 0)
        self.assertEqual(len({r["case_id"] for r in rows}), len(rows))
        self.assertEqual(sum(a["summary"]["tests"] for a in doc["areas_detail"]), 2188)
        self.assertTrue(all(c["status"] == "pass" for c in doc["checks"]))

    def test_run3b_adm(self):
        doc, _ = self.conv("ntdll-run3b-adm.serial.log", require_payload_exit=True)
        c = doc["summary"]["counts"]
        self.assertEqual((c["fail"], c["skip"]), (0, 1))
        self.assertEqual(doc["outcome"], ["success"])
        self.assertEqual(doc["mode"], "admin")

    def test_run3_has_two_failures(self):
        doc, rows = self.conv("ntdll-run3-std.serial.log")
        fails = sorted(r["case_id"] for r in rows if r["status"] == "fail")
        self.assertEqual(fails, ["nt_sync/nt_sync_delay_zero_returns",
                                 "nt_thread/nt_thread_critical_flag_clear"])
        self.assertEqual(doc["outcome"], ["failure"])
        self.assertTrue(doc["complete"])
        self.assertIn("0x40000024", next(r for r in rows if r["status"] == "fail")["message"])

    def test_every_real_log_matches_summary_lines(self):
        for n in ("ntdll-run3-std.serial.log", "ntdll-run3-adm.serial.log",
                  "ntdll-run3b-std.serial.log", "ntdll-run3b-adm.serial.log",
                  "r4-std.serial.log", "r5-std.serial.log"):
            if not real(n):
                continue
            doc, rows = self.conv(n)
            self.assertEqual(len(doc["summary"]["areas"]), 34, n)
            self.assertEqual(doc["checks"][2]["status"], "pass", n)           # areas.complete
            self.assertEqual(doc["checks"][3]["status"], "pass", n)           # summary.consistent
            failed = sum(a["summary"]["failed"] for a in doc["areas_detail"])
            self.assertEqual(failed, doc["summary"]["counts"]["fail"], n)

    def test_cli_and_compare_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            for tag, log in (("o", "ntdll-run3b-std.serial.log"), ("i", "ntdll-run3-std.serial.log")):
                r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "ntdll_result.py"),
                                    "convert", "--serial", real(log), "--out",
                                    os.path.join(d, tag), "--exit-zero"],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                for f in ("cases.jsonl", "result.json", "areas.tsv"):
                    self.assertTrue(os.path.getsize(os.path.join(d, tag, f)) > 0)
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "ntdll_result.py"),
                                "compare", "--oracle", os.path.join(d, "o", "cases.jsonl"),
                                "--i7", os.path.join(d, "i", "cases.jsonl"),
                                "--out", os.path.join(d, "cmp")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stdout)  # 2 new diffs gate
            s = json.load(open(os.path.join(d, "cmp", "compare.json")))
            self.assertEqual((s["diff"], s["i7_missing"], s["same"]), (2, 0, 2186))
            base = os.path.join(d, "base.tsv")
            with open(base, "w") as f:
                f.write("# known\nnt_sync/nt_sync_delay_zero_returns\tx\n"
                        "nt_thread/nt_thread_critical_flag_clear\ty\n")
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "ntdll_result.py"),
                                "compare", "--oracle", os.path.join(d, "o", "cases.jsonl"),
                                "--i7", os.path.join(d, "i", "cases.jsonl"),
                                "--baseline", base, "--out", os.path.join(d, "cmp2")],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)


class Cli(unittest.TestCase):
    def test_env_expansion_and_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "s.log")
            open(log, "w").write(synth(["x_a"]) + "I7RES done\r\n")
            af = os.path.join(d, "areas")
            open(af, "w").write("x_a\n")
            env = dict(os.environ, BBTEST_OUT_DIR=d)
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "ntdll_result.py"),
                                "convert", "--serial", log, "--areas-file", af,
                                "--out", "$BBTEST_OUT_DIR/o", "--prefix", "p."],
                               env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(d, "o", "p.cases.jsonl")))
            self.assertTrue(os.path.exists(os.path.join(d, "o", "p.result.json")))


class Pack(unittest.TestCase):
    def fake_build(self, d):
        b = os.path.join(d, "build")
        os.makedirs(b)
        for a in pp.expected_areas():
            with open(os.path.join(b, a + ".exe"), "wb") as f:
                f.write(b"MZ" + a.encode())
        return b

    def test_areas_are_34(self):
        self.assertEqual(len(pp.expected_areas()), 34)
        self.assertEqual(pp.expected_areas(), sorted(pp.expected_areas()))

    def test_artifact_is_deterministic_and_complete(self):
        with tempfile.TemporaryDirectory() as d:
            b = self.fake_build(d)
            for o in ("o1", "o2"):
                pp.main(["artifact", "--build-dir", b, "--out", os.path.join(d, o)])
            t1 = open(os.path.join(d, "o1", "ntdll-build.tar"), "rb").read()
            t2 = open(os.path.join(d, "o2", "ntdll-build.tar"), "rb").read()
            self.assertEqual(hashlib.sha256(t1).digest(), hashlib.sha256(t2).digest())
            self.assertEqual(len(open(os.path.join(d, "o1", "build-manifest.txt")).readlines()), 34)
            os.remove(os.path.join(b, "rtl_time.exe"))
            with self.assertRaises(SystemExit):
                pp.main(["artifact", "--build-dir", b, "--out", os.path.join(d, "o3")])

    def test_payload_from_tar(self):
        with tempfile.TemporaryDirectory() as d:
            b = self.fake_build(d)
            pp.main(["artifact", "--build-dir", b, "--out", os.path.join(d, "art")])
            pp.main(["payload", "--build", os.path.join(d, "art", "ntdll-build.tar"),
                     "--mode", "std", "--out", os.path.join(d, "p")])
            cmd = open(os.path.join(d, "p", "run.cmd"), "rb").read()
            self.assertIn(b"-Mode std >COM1 2>&1\r\n", cmd)
            self.assertEqual(len(os.listdir(os.path.join(d, "p", "build"))), 34)
            with self.assertRaises(SystemExit):   # refuses a non-empty out
                pp.main(["payload", "--build", b, "--mode", "adm", "--out", os.path.join(d, "p")])

    @unittest.skipUnless(os.path.exists(os.path.join(CORPUS, "payload-std", "run.cmd")),
                         "reference payloads not present")
    def test_matches_the_payloads_used_for_run3(self):
        with tempfile.TemporaryDirectory() as d:
            b = self.fake_build(d)
            for mode, ref in (("std", "payload-std"), ("adm", "payload-adm")):
                out = os.path.join(d, mode)
                pp.main(["payload", "--build", b, "--mode", mode, "--out", out, "--eol", "lf"])
                self.assertEqual(open(os.path.join(out, "run.cmd"), "rb").read(),
                                 open(os.path.join(CORPUS, ref, "run.cmd"), "rb").read(), mode)
                # runner.ps1 differs from run3's only in the (now random) throwaway password
                new = open(os.path.join(out, "runner.ps1")).read().splitlines()
                old = open(os.path.join(CORPUS, ref, "runner.ps1")).read().splitlines()
                keep = lambda ls: [l for l in ls if "Pass-9x" not in l and "$pw" not in l]
                self.assertEqual(keep(new), keep(old), mode)


if __name__ == "__main__":
    unittest.main()
