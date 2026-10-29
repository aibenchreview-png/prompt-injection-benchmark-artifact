import json,glob,collections,re,ast,sys
exec(open('func.py').read().split('c=collections.Counter()')[0].replace('rows=[json.loads(l) for l in open(sys.argv[1])]','rows=[]'))
FUNC={'compare','compare-const','used-in-func','default-arg'}
print('%-24s %-9s %6s %7s %6s %6s'%('backbone','gate','n','strict','dead','func'))
for f in sorted(glob.glob('*/g4live_trials_*.jsonl')):
    name=f.split('g4live_trials_')[1][:-6]
    rs=[json.loads(l) for l in open(f)]
    att=[r for r in rs if r.get('role')=='att' and r.get('gate')]
    for g in ('off','on','complete'):
        a=[r for r in att if r['gate']==g]
        st=[r for r in a if r.get('eff_strict')]
        cl=collections.Counter()
        for r in st:
            s=content(r.get('raw',''))
            cl[cls(s) if s else 'noparse']+=1
        fn=sum(v for k,v in cl.items() if k in FUNC)
        print('%-24s %-9s %6d %7d %6d %6d'%(name,g,len(a),len(st),cl.get('dead-const',0),fn))
