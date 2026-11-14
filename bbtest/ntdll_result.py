#!/usr/bin/env python3
"""Convert ntdll corpus run logs into bbtest.result/1 pieces.

Stdlib only (python3.8+). Subcommands:

  convert   one serial log (I7RES framing) -> cases.jsonl, result.json, areas.tsv
  compare   oracle cases.jsonl vs i7 cases.jsonl -> compare.tsv, compare.json

Log grammar (see common/t.c in the corpus and runner.ps1):

  I7RES mode=std|adm
  I7RES end <area> rc=<n|TIMEOUT|LAUNCHERR ...> secs=<n>   (precedes the block)
  I7RES timeout <area>
  I7RES begin <area>
  I7RES | RUN  <case>
  I7RES | OK   <case> | FAIL <case> | SKIP <case>          (case verdict)
  I7RES |   FAIL file:line: expr | SKIP reason | NOTE ...   (detail, indented)
  I7RES | SUMMARY tests=N failed=N skipped=N checks_pass=N checks_fail=N
  I7RES finish <area>
  I7RES done
  I7VM: payload exit N                                      (oracle only)

The converter never hides a failure: a case that started (RUN) and has no
verdict becomes `error` (or `timeout` in a timed-out area); an area without a
SUMMARY is incomplete. Required assertions mean "the harness ran to the end"
(i7res.done, ntdll.areas.complete); case failures show in the outcome and the
summary, not in completeness.
"""
import argparse
import json
import os
import re
import sys

SCHEMA_RESULT = "bbtest.result/1"
HERE = os.path.dirname(os.path.abspath(__file__))


def default_areas():
    p = os.path.join(HERE, "areas.txt")
    with open(p) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


class Area:
    def __init__(self, name):
        self.name = name
        self.cases = []          # dicts: name, status, message, offset
        self.summary = None      # dict of ints
        self.rc = None
        self.secs = None
        self.timeout = False
        self.finished = False
        self.fatal = []
        self.notes = 0
        self.begin_offset = None
        self.runs = 0

    @property
    def complete(self):
        return self.summary is not None and not self.timeout


class Run:
    def __init__(self):
        self.mode = None
        self.areas = {}
        self.order = []
        self.done = False
        self.done_offset = None
        self.payload_exit = None
        self.payload_exit_offset = None
        self.logon = False


def _norm(line):
    return line.rstrip("\r\n").rstrip("\r")


def parse_log(data):
    """Parse bytes of a serial log into a Run."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    run = Run()
    area_for = {}   # end/timeout lines arrive before `begin`
    cur = None
    pending = None  # (name, offset, detail[])
    off = 0
    for raw in data.splitlines(keepends=True):
        here = off
        off += len(raw)
        line = _norm(raw.decode("utf-8", "replace"))

        def get(name):
            a = run.areas.get(name)
            if a is None:
                a = Area(name)
                run.areas[name] = a
                run.order.append(name)
            return a

        m = re.match(r"I7VM: payload exit (\d+)", line)
        if m:
            run.payload_exit = int(m.group(1))
            run.payload_exit_offset = here
            continue
        if line.startswith("I7VM: logon"):
            run.logon = True
            continue
        m = re.match(r"I7RES mode=(\S+)", line)
        if m:
            run.mode = m.group(1)
            continue
        if line.rstrip() == "I7RES done":
            run.done = True
            run.done_offset = here
            continue
        m = re.match(r"I7RES end (\S+) rc=(\S*)(?: secs=(\d+))?", line)
        if m:
            a = get(m.group(1))
            a.rc = m.group(2)
            a.secs = int(m.group(3)) if m.group(3) else None
            continue
        m = re.match(r"I7RES timeout (\S+)", line)
        if m:
            get(m.group(1)).timeout = True
            continue
        m = re.match(r"I7RES begin (\S+)", line)
        if m:
            cur = get(m.group(1))
            cur.begin_offset = here
            pending = None
            continue
        m = re.match(r"I7RES finish (\S+)", line)
        if m:
            a = get(m.group(1))
            a.finished = True
            if pending is not None and cur is a:
                _close_pending(a, pending, "error", "started, no verdict")
            pending = None
            cur = None
            continue
        if cur is None or not line.startswith("I7RES |"):
            continue
        body = line[8:] if line.startswith("I7RES | ") else ""
        if body.startswith("  "):
            t = body.strip()
            if t.startswith("FAIL") and pending is not None:
                pending[2].append(t[4:].strip())
            elif t.startswith("NOTE"):
                cur.notes += 1
            continue
        parts = body.split(None, 1)
        if not parts:
            continue
        tok = parts[0]
        rest = parts[1].strip() if len(parts) > 1 else ""
        if tok == "RUN":
            if pending is not None:
                _close_pending(cur, pending, "error", "started, no verdict")
            cur.runs += 1
            pending = [rest, here, []]
        elif tok in ("OK", "FAIL", "SKIP"):
            status = {"OK": "pass", "FAIL": "fail", "SKIP": "skip"}[tok]
            det = []
            off0 = here
            if pending is not None and pending[0] == rest:
                det = pending[2]
                off0 = pending[1]
            elif pending is not None:
                _close_pending(cur, pending, "error", "started, no verdict")
            pending = None
            msg = "; ".join(det) if det else None
            cur.cases.append({"name": rest, "status": status, "message": msg, "offset": off0})
        elif tok == "SUMMARY":
            try:
                cur.summary = {k: int(v) for k, v in
                               (p.split("=", 1) for p in rest.split() if "=" in p)}
            except ValueError:
                cur.summary = None
        elif tok == "FATAL":
            cur.fatal.append(rest)
    if cur is not None and pending is not None:
        _close_pending(cur, pending, "error", "started, no verdict")
    return run


def _close_pending(area, pending, status, why):
    status = "timeout" if (status == "error" and area.timeout) else status
    area.cases.append({"name": pending[0], "status": status,
                       "message": why if not pending[2] else why + "; " + "; ".join(pending[2]),
                       "offset": pending[1]})


def case_rows(run, env_dependent=()):
    """CaseRecord rows (bbtest.cases/1), area order stable (sorted)."""
    rows = []
    for name in sorted(run.areas):
        a = run.areas[name]
        # a RUN still open at end of log (no `finish`) is also unterminated
        seen = {}
        for c in a.cases:
            n = seen.get(c["name"], 0) + 1
            seen[c["name"]] = n
            cid = "%s/%s" % (name, c["name"]) + ("#%d" % n if n > 1 else "")
            row = {"case_id": cid, "area": name, "name": c["name"], "status": c["status"]}
            if name in env_dependent:
                row["class"] = "env_dependent"
            if c["message"]:
                row["message"] = c["message"][:500]
            rows.append(row)
    return rows


def summarize(rows):
    areas = {}
    counts = {"pass": 0, "fail": 0, "error": 0, "timeout": 0, "skip": 0, "excluded": 0, "total": 0}
    classes = {}
    for r in rows:
        a = areas.setdefault(r["area"], {"area": r["area"], "pass": 0, "fail": 0, "missing": 0})
        s = r["status"]
        counts["total"] += 1
        counts[s] = counts.get(s, 0) + 1
        if s == "pass":
            a["pass"] += 1
        elif s in ("fail", "timeout"):
            a["fail"] += 1
        elif s == "skip":
            a["skip"] = a.get("skip", 0) + 1
        else:
            a["error"] = a.get("error", 0) + 1
        if r.get("class"):
            classes[r["class"]] = classes.get(r["class"], 0) + 1
    return {"counts": counts, "areas": [areas[k] for k in sorted(areas)], "classes": classes}


def build_checks(run, expected, require_payload_exit):
    checks = []

    def chk(cid, status, required, evidence=None):
        c = {"id": cid, "kind": "assertion", "required": required, "status": status}
        if evidence:
            c["evidence"] = evidence
        checks.append(c)

    chk("i7res.done", "pass" if run.done else "missing", True,
        "serial.log@%d" % run.done_offset if run.done else None)
    if require_payload_exit:
        ok = run.payload_exit == 0
        chk("payload.exit0",
            "pass" if ok else ("missing" if run.payload_exit is None else "fail"), True,
            "serial.log@%d" % run.payload_exit_offset if run.payload_exit is not None else None)
    missing = [n for n in expected if n not in run.areas or not run.areas[n].complete]
    chk("ntdll.areas.complete", "pass" if not missing else "missing", True)
    # SUMMARY.tests must equal the verdicts we counted.
    bad = []
    for n, a in run.areas.items():
        if a.summary is not None and "tests" in a.summary:
            if a.summary["tests"] != len(a.cases):
                bad.append(n)
    chk("ntdll.summary.consistent", "pass" if not bad else "fail", False)
    for n in expected:
        a = run.areas.get(n)
        if a is None or not a.complete:
            st = "error" if (a is not None and a.timeout) else "missing"
        elif a.summary.get("failed", 0) or a.summary.get("checks_fail", 0):
            st = "fail"
        else:
            st = "pass"
        chk("area.%s" % n, st, False,
            "serial.log@%d" % a.begin_offset if a is not None and a.begin_offset is not None else None)
    return checks, missing, bad


def convert(data, expected=None, mode=None, env_dependent=(), require_payload_exit=False,
            min_cases=None):
    run = parse_log(data)
    expected = list(expected) if expected is not None else default_areas()
    rows = case_rows(run, env_dependent)
    summ = summarize(rows)
    checks, missing, inconsistent = build_checks(run, expected, require_payload_exit)
    # areas that never reported still appear, as missing (nothing hidden)
    have = {a["area"] for a in summ["areas"]}
    for n in expected:
        if n not in have:
            summ["areas"].append({"area": n, "pass": 0, "fail": 0, "missing": 1})
    summ["areas"].sort(key=lambda a: a["area"])
    c = summ["counts"]
    timeouts = [n for n, a in run.areas.items() if a.timeout]
    outcome = []
    if c["fail"]:
        outcome.append("failure")
    if timeouts or c["timeout"]:
        outcome.append("timeout")
    if c["error"] or missing or not run.done or inconsistent or \
            (require_payload_exit and run.payload_exit is None):
        outcome.append("error")
    if require_payload_exit and run.payload_exit not in (None, 0) and "failure" not in outcome:
        outcome.append("failure")
    if not outcome:
        outcome = ["success"]
    order = {"success": 0, "failure": 1, "timeout": 2, "error": 3}
    outcome.sort(key=order.get)
    required_ids = [c_["id"] for c_ in checks if c_["required"]]
    complete = all(c_["status"] == "pass" for c_ in checks if c_["required"])
    if min_cases is not None and c["total"] < min_cases:
        complete = False
    areas_detail = []
    for n in expected + sorted(set(run.areas) - set(expected)):
        a = run.areas.get(n)
        areas_detail.append({
            "area": n,
            "state": "absent" if a is None else ("timeout" if a.timeout else
                     ("complete" if a.summary is not None else "incomplete")),
            "rc": a.rc if a else None, "secs": a.secs if a else None,
            "summary": a.summary if a else None,
            "fatal": a.fatal[:5] if a else [],
        })
    doc = {
        "schema": SCHEMA_RESULT,
        "_fragment": "worker-side pieces only: merge with ids, profile, worker, timing, artifacts",
        "mode": mode or run.mode,
        "checks": checks,
        "required_assertions": required_ids,
        "summary": summ,
        "complete": complete,
        "outcome": outcome,
        "payload_exit": run.payload_exit,
        "areas_detail": areas_detail,
    }
    return doc, rows


def write_outputs(doc, rows, out, prefix=""):
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, prefix + "cases.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    with open(os.path.join(out, prefix + "result.json"), "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(os.path.join(out, prefix + "areas.tsv"), "w") as f:
        f.write("area\tstate\ttests\tfailed\tskipped\tchecks_pass\tchecks_fail\trc\tsecs\n")
        for a in doc["areas_detail"]:
            s = a["summary"] or {}
            f.write("\t".join(str(x) for x in (
                a["area"], a["state"], s.get("tests", ""), s.get("failed", ""),
                s.get("skipped", ""), s.get("checks_pass", ""), s.get("checks_fail", ""),
                a["rc"] if a["rc"] is not None else "", a["secs"] if a["secs"] is not None else "")) + "\n")


def load_cases(path):
    with open(path) as f:
        return {r["case_id"]: r for r in (json.loads(l) for l in f if l.strip())}


def compare(oracle, i7, allowed=()):
    """Join by case_id. The oracle is the reference.

    A difference is: status differs, or the case is missing on one side.
    Differences listed in `allowed` are labelled `known`, never dropped.
    A case missing on the i7 side makes the comparison incomplete."""
    rows = []
    for cid in sorted(set(oracle) | set(i7)):
        o = oracle.get(cid)
        i = i7.get(cid)
        os_ = o["status"] if o else "missing"
        is_ = i["status"] if i else "missing"
        if os_ == is_:
            verdict = "same"
        else:
            verdict = "known" if cid in allowed else "diff"
        rows.append({"case_id": cid, "area": (o or i)["area"], "oracle": os_, "i7": is_,
                     "verdict": verdict})
    n = lambda v: sum(1 for r in rows if r["verdict"] == v)
    new_diffs = [r for r in rows if r["verdict"] == "diff"]
    incomplete = [r for r in rows if r["i7"] == "missing"]
    out = []
    if new_diffs:
        out.append("failure")
    if incomplete:
        out.append("error")
    return rows, {"cases": len(rows), "same": n("same"), "known": n("known"), "diff": n("diff"),
                  "i7_missing": len(incomplete),
                  "oracle_missing": sum(1 for r in rows if r["oracle"] == "missing"),
                  "outcome": out or ["success"]}


def cmd_convert(a):
    with open(a.serial, "rb") as f:
        data = f.read()
    areas = None
    if a.areas_file:
        with open(a.areas_file) as f:
            areas = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    doc, rows = convert(data, areas, a.mode, tuple(a.env_dependent), a.require_payload_exit,
                        a.min_cases)
    write_outputs(doc, rows, a.out, a.prefix)
    c = doc["summary"]["counts"]
    print("areas=%d cases=%d pass=%d fail=%d skip=%d error=%d timeout=%d complete=%s outcome=%s"
          % (len([x for x in doc["areas_detail"] if x["state"] != "absent"]), c["total"],
             c["pass"], c["fail"], c["skip"], c["error"], c["timeout"], doc["complete"],
             ",".join(doc["outcome"])))
    return 0 if doc["outcome"] == ["success"] else 1 if not a.exit_zero else 0


def cmd_compare(a):
    allowed = set()
    if a.baseline:
        with open(a.baseline) as f:
            allowed = {l.split("\t")[0].strip() for l in f if l.strip() and not l.startswith("#")}
    rows, summ = compare(load_cases(a.oracle), load_cases(a.i7), allowed)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "compare.tsv"), "w") as f:
        f.write("case_id\tarea\toracle\ti7\tverdict\n")
        for r in rows:
            if r["verdict"] != "same" or a.all:
                f.write("%(case_id)s\t%(area)s\t%(oracle)s\t%(i7)s\t%(verdict)s\n" % r)
    with open(os.path.join(a.out, "compare.json"), "w") as f:
        json.dump(summ, f, indent=1, sort_keys=True)
        f.write("\n")
    print(json.dumps(summ, sort_keys=True))
    return 0 if summ["outcome"] == ["success"] or a.exit_zero else 1


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("convert")
    c.add_argument("--serial", required=True)
    c.add_argument("--out", default=os.environ.get("BBTEST_OUT_DIR", "."))
    c.add_argument("--prefix", default="", help="output file name prefix, e.g. oracle-std.")
    c.add_argument("--mode")
    c.add_argument("--areas-file", help="expected areas, one per line (default: areas.txt)")
    c.add_argument("--env-dependent", action="append", default=[])
    c.add_argument("--require-payload-exit", action="store_true",
                   help="oracle logs: require `I7VM: payload exit 0`")
    c.add_argument("--min-cases", type=int)
    c.add_argument("--exit-zero", action="store_true", help="always exit 0 (record, do not gate)")
    c.set_defaults(fn=cmd_convert)
    d = sub.add_parser("compare")
    d.add_argument("--oracle", required=True, help="oracle cases.jsonl")
    d.add_argument("--i7", required=True, help="i7 cases.jsonl")
    d.add_argument("--baseline", help="file of known-differing case_ids (first tab column)")
    d.add_argument("--out", default=os.environ.get("BBTEST_OUT_DIR", "."))
    d.add_argument("--all", action="store_true", help="also list identical cases")
    d.add_argument("--exit-zero", action="store_true")
    d.set_defaults(fn=cmd_compare)
    a = p.parse_args(argv)
    # $VAR in path arguments (steps are argv arrays: no shell to expand them)
    for k in ("serial", "out", "areas_file", "oracle", "i7", "baseline"):
        if getattr(a, k, None):
            setattr(a, k, os.path.expandvars(getattr(a, k)))
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
