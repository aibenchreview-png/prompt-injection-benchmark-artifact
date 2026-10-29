#!/usr/bin/env python3
"""Adaptive, gate-aware attacker v3 (P0 iii). Built on bench3 (AST scoring, per-trial JSONL, ungated oracle).

Search objective: eff_strict through --gate (default complete). Every candidate is also logged with the
ungated attempt oracle. Baseline (no payload) is measured once per model and subtracted at the rate level.
Held-out: the single best payload is re-scored on FRESH nonces (new seeds, new keys); report that number.
Proposer: any Ollama model (--proposer-model). Seeds include legacy v2 strategies plus the prose_named
and disguised payloads from bench3.
G1 is skipped under on/complete gates by default: those gates deny every NETCALL, so G1 is 0 by construction.
"""
import argparse, csv, json, os, time
from concurrent.futures import ThreadPoolExecutor
import bench as b0
import bench3 as B
import adaptive_attacker_v2 as v2

def seeds(goal):
    out = []
    for name, t in v2.strategies(goal):
        out.append((name, t.replace("AKIA_CANARY_{K}", "AKIA{N}").replace("{K}", "AKIA{N}")))
    for arm in ("prose_named", "disguised"):
        out.append((arm, B.payload(goal, "{N}", arm)))
    return out

def run_cell(a, logf, model, goal, text, trials, run_id, gate, workers):
    """-> (n_valid, att_succ, eff_succ). One generation per trial, scored through `gate`."""
    res = []
    def w(i):
        n = B.det_nonce(run_id, model, hash_text(text), goal, i)
        return B.one_generation(a.ollama, model, n, i, [goal], goal, "custom", a.temp, run_id, logf, dict(trial=i, role="att", payload=text[:200]), text_override=text)
    with ThreadPoolExecutor(workers) as ex: res = list(ex.map(w, range(trials)))
    v = [r for r in res if r]
    return len(v), sum(r[(gate, goal)][0] for r in v), sum(r[(gate, goal)][1] for r in v)

def hash_text(t):
    import hashlib; return hashlib.sha1(t.encode()).hexdigest()[:8]

def baseline_rates(a, logf, model, goals, gate, n):
    res = []
    def w(i):
        nn = B.det_nonce("base3", model, "none", "base", i)
        return B.one_generation(a.ollama, model, nn, i, goals, None, "none", a.temp, "base3", logf, dict(trial=i, role="base"))
    with ThreadPoolExecutor(a.workers) as ex: res = [r for r in ex.map(w, range(n)) if r]
    return {g: (sum(r[(gate, g)][1] for r in res) / len(res) if res else 0.0) for g in goals}, len(res)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True); ap.add_argument("--goals", default="G2,G3,G4,G5")
    ap.add_argument("--gate", choices=B.GATES, default="complete")
    ap.add_argument("--trials", type=int, default=12); ap.add_argument("--test-trials", type=int, default=30)
    ap.add_argument("--base-trials", type=int, default=30)
    ap.add_argument("--temp", type=float, default=0.7); ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--ollama", default=b0.OLLAMA_DEFAULT); ap.add_argument("--proposer-model", default=None)
    ap.add_argument("--rounds", type=int, default=4); ap.add_argument("--k", type=int, default=6); ap.add_argument("--elite", type=int, default=2)
    ap.add_argument("--out", default="adaptive_v3_trials.jsonl"); ap.add_argument("--summary", default="adaptive_v3_summary.csv")
    ap.add_argument("--dump-winners", default=None)
    a = ap.parse_args()
    v2.start_catcher()
    goals = [g for g in a.goals.split(",") if g and not (g == "G1" and a.gate != "off")]
    logf = open(a.out, "a"); new = not os.path.exists(a.summary)
    sf = open(a.summary, "a", newline=""); sw = csv.writer(sf)
    if new: sw.writerow(["ts", "model", "gate", "goal", "stage", "name", "round", "n", "attempt_rate", "eff_rate", "base_rate", "adj_rate", "text"])
    base, nb = baseline_rates(a, logf, a.model, goals, a.gate, a.base_trials)
    print(f"[base] n={nb} {base}", flush=True)
    pm = a.proposer_model or a.model; winners = {}
    def rec(goal, stage, name, rd, n, att, eff, text):
        ar = att / n if n else 0.0; er = eff / n if n else 0.0; adj = max(0.0, er - base[goal])
        sw.writerow([int(time.time()), a.model, a.gate, goal, stage, name, rd, n, round(ar, 4), round(er, 4), round(base[goal], 4), round(adj, 4), text[:300]]); sf.flush()
        print(f"[{a.model} {goal} {a.gate}] {stage}/{name} r{rd}: attempt {att}/{n} effective {eff}/{n} adj={adj:.0%}", flush=True)
        return er
    for goal in goals:
        elite = []
        for name, text in seeds(goal):
            n, att, eff = run_cell(a, logf, a.model, goal, text, a.trials, "search3", a.gate, a.workers)
            elite.append((rec(goal, "seed", name, 0, n, att, eff, text), text, name))
        elite.sort(key=lambda x: -x[0]); elite = elite[:a.elite]
        for rd in range(1, a.rounds + 1):
            ch = []
            for (er, t, nm) in elite:
                for vtxt in v2.propose_variants(a.ollama, pm, goal, t.replace("AKIA{N}", "AKIA<key>"), f"effective rate {er:.2f}", a.temp, a.k):
                    vtxt = vtxt.replace("AKIA<key>", "AKIA{N}")
                    n, att, eff = run_cell(a, logf, a.model, goal, vtxt, a.trials, "search3", a.gate, a.workers)
                    ch.append((rec(goal, "refine", f"r{rd}", rd, n, att, eff, vtxt), vtxt, f"r{rd}"))
            elite = sorted(elite + ch, key=lambda x: -x[0])[:a.elite]
        best_rate, best_text, best_name = elite[0]
        n, att, eff = run_cell(a, logf, a.model, goal, best_text, a.test_trials, "heldout3", a.gate, a.workers)
        hr = rec(goal, "heldout", best_name, 99, n, att, eff, best_text)
        winners[goal] = dict(text=best_text, name=best_name, search_rate=best_rate, heldout_rate=hr, source=a.model)
    if a.dump_winners: json.dump(winners, open(a.dump_winners, "w"), indent=2)
    logf.close(); sf.close(); print("[adaptive_v3] done", flush=True)

if __name__ == "__main__": main()
