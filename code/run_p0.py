#!/usr/bin/env python3
"""P0(i)+(ii) runner. Per model: N baseline generations (no payload, scored on every goal)
plus N attacked generations per (arm, goal). One generation is scored under gates off/on/complete.
Resumable: nonces already in the JSONL are skipped. Paired design: attacked trial i and baseline trial i
share the task (TASKS[i % 6]).
"""
import argparse, json, os, sys, time
from concurrent.futures import ThreadPoolExecutor
import bench as b0
import bench3 as B
import adaptive_attacker_v2 as v2

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", required=True)
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--arms", default="explicit,disguised,prose_named")
    ap.add_argument("--goals", default="G1,G2,G3,G4,G5")
    ap.add_argument("--ollama", default=b0.OLLAMA_DEFAULT)
    ap.add_argument("--temp", type=float, default=0.7)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default="p0_trials.jsonl")
    ap.add_argument("--run-id", default="p0")
    ap.add_argument("--limit", type=int, default=0, help="debug: stop after this many generations")
    a = ap.parse_args()
    v2.start_catcher()
    models = [m for m in a.models.split(",") if m]; arms = a.arms.split(","); goals = a.goals.split(",")
    done = set()
    if os.path.exists(a.out):
        for l in open(a.out):
            try: r = json.loads(l); done.add(r["nonce"])
            except Exception: pass
    jobs = []
    for m in models:
        for i in range(a.trials):
            n = B.det_nonce(a.run_id, m, "none", "base", i)
            if n not in done: jobs.append((m, n, i, None, "none"))
        for arm in arms:
            for g in goals:
                for i in range(a.trials):
                    n = B.det_nonce(a.run_id, m, arm, g, i)
                    if n not in done: jobs.append((m, n, i, g, arm))
    if a.limit: jobs = jobs[:a.limit]
    print(f"[p0] {len(jobs)} generations to run ({len(done)} already done)", flush=True)
    logf = open(a.out, "a"); t0 = time.time(); cnt = [0]
    def work(j):
        m, n, i, g, arm = j
        meta = dict(trial=i, role="base" if g is None else "att")
        ok = B.one_generation(a.ollama, m, n, i, goals, g, arm, a.temp, a.run_id, logf, meta)
        cnt[0] += 1
        if cnt[0] % 25 == 0: print(f"[p0] {cnt[0]}/{len(jobs)} {time.time()-t0:.0f}s", flush=True)
    with ThreadPoolExecutor(a.workers) as ex: list(ex.map(work, jobs))
    logf.close(); print("[p0] done", flush=True)

if __name__ == "__main__": main()
