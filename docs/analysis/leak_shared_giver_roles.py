# Two anonymous lists (giver pseudonyms G, recipient pseudonyms R). Public permutations sigma_t
# (uniform), t* = first t with no hidden fixed point. Question: how well can participant A
# guess "my giver is my recipient B" (mutual pair) from public data + own knowledge?
import random, itertools, sys
from collections import defaultdict
def run(n, trials, use_history):
    persons=list(range(n)); A=0
    stats=defaultdict(lambda:[0,0])  # posterior bucket -> [count, mutual]
    for _ in range(trials):
        g=list(range(n)); random.shuffle(g)   # g[i]=giver-position of person i
        r=list(range(n)); random.shuffle(r)
        sigmas=[]
        while True:
            s=list(range(n)); random.shuffle(s); sigmas.append(s)
            if all(s[g[i]]!=r[i] for i in persons): break
        star=sigmas[-1]; hist=sigmas[:-1] if use_history else []
        # A's recipient B: person with r[B]==star[g[A]]
        B=r.index(star[g[A]])
        truth = star[g[B]]==r[A]
        # A knows g[A], r[A], r[B]. Enumerate unknowns: assignment of remaining g positions to persons !=A,
        # remaining r positions to persons not in {A,B}.
        gpos=[x for x in range(n) if x!=g[A]]; rpos=[x for x in range(n) if x not in (r[A],r[B])]
        others=[p for p in persons if p!=A]; oth2=[p for p in persons if p not in (A,B)]
        w=0; wm=0
        for gp in itertools.permutations(gpos):
            G={A:g[A]}; G.update(zip(others,gp))
            for rp in itertools.permutations(rpos):
                R={A:r[A],B:r[B]}; R.update(zip(oth2,rp))
                if any(star[G[i]]==R[i] for i in persons): continue
                if any(all(s[G[i]]!=R[i] for i in persons) for s in hist): continue
                w+=1; wm+= star[G[B]]==R[A]
        post=wm/w
        b=round(post,1); stats[b][0]+=1; stats[b][1]+=truth
    return stats
for n in (4,5,6):
    for h in (False,True):
        st=run(n, 3000 if n<6 else 600, h)
        tot=sum(c for c,_ in st.values())
        print(f"n={n} history={h}: " + ", ".join(f"P≈{k}: {c/tot:.0%}" for k,(c,m) in sorted(st.items())))
