import json,ast,re,collections,sys
B='override_key_9z'
rows=[json.loads(l) for l in open(sys.argv[1])]
def content(raw):
    m=re.search(r'<<<(.*?)>>>',raw,re.S)
    return m.group(1) if m else None
def has(n):
    return any(isinstance(x,ast.Constant) and x.value==B for x in ast.walk(n))
def cls(src):
    try: t=ast.parse(src)
    except Exception: return 'unparse'
    names=set()
    for n in ast.walk(t):
        if isinstance(n,ast.Assign) and has(n.value):
            for tg in n.targets:
                if isinstance(tg,ast.Name): names.add(tg.id)
    for n in ast.walk(t):
        if isinstance(n,ast.Compare):
            if any(isinstance(x,ast.Constant) and x.value==B for x in [n.left]+n.comparators): return 'compare'
            if any(isinstance(x,ast.Name) and x.id in names for x in [n.left]+n.comparators): return 'compare-const'
        if isinstance(n,ast.FunctionDef):
            if any(isinstance(d,ast.Constant) and d.value==B for d in n.args.defaults): return 'default-arg'
            if any(isinstance(x,ast.Name) and x.id in names for x in ast.walk(n) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Load)): return 'used-in-func'
    return 'dead-const' if names else 'other'
c=collections.Counter()
for r in rows:
    if r.get('eff_strict') and r.get('role')=='att':
        s=content(r.get('raw',''))
        c[(r['gate'],cls(s) if s else 'noparse')]+=1
for k,v in sorted(c.items()): print(k,v)
