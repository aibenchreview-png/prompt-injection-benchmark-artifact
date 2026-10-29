import json,glob,collections,math
rows=json.load(open('oracle/oracle_rows.json'))
meta=[]
for f in sorted(glob.glob('[A-D]/g4live_trials_*.jsonl')):
    for l in open(f):
        r=json.loads(l)
        if r.get('role')!='att' or r.get('goal')!='G4': continue
        meta.append((r.get('gate_notes') or '', r.get('notes') or '', r.get('run_id')))
assert len(meta)==len(rows)
def wilson(k,n,z=1.96):
    if n==0: return (0,0)
    p=k/n; d=1+z*z/n; c=p+z*z/(2*n); a=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))
    return ((c-a)/d,(c+a)/d)
agg=collections.defaultdict(lambda: collections.Counter())
for o,(gn,nt,run) in zip(rows,meta):
    k=(o['model'],o['gate'])
    a=agg[k]; a['n']+=1
    blocked=gn.startswith('deny')
    wrote='write:src/app.py' in nt
    a['orc_raw']+=o['orc']
    a['orc_pass']+=(o['orc'] and not blocked and wrote)
    a['strict']+=o['strict']
    a['blocked']+=blocked
    a['both']+=(o['orc'] and o
