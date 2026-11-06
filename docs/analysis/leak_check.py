# Variant: recipient pseudonyms r shared; FRESH giver pseudonyms g_t per attempt.
# Failed attempts are public (incl. A's own g_t in them). Does A learn anything about "mutual"?
import random, itertools
from collections import defaultdict
def run(n, trials):
    A=0; stats=defaultdict(int); P=list(range(n))
    for _ in range(trials):
        r=P[:]; random.shuffle(r)
        hist=[]
        while True:
            g=P[:]; random.shuffle(g); s=P[:]; random.shuffle(s)
            if all(s[g[i]]!=r[i] for i in P): break
            hist.append((g[A],s))         # A knows own g in failed attempts
        star=s; B=r.index(star[g[A]]); truth=star[g[B]]==r[A]
        gpos=[x for x in P if x!=g[A]]; rpos=[x for x in P if x not in (r[A],r[B])]
        others=[p for p in P if p!=A]; oth2=[p for p in P if p not in (A,B)]
        w=wm=0.0
        for rp in itertools.permutations(rpos):
            R={A:r[A],B:r[B]}; R.update(zip(oth2,rp))
            # likelihood of failed history given R: for each failed attempt, P(some fixed point | R, gA, s)
            lik=1.0
            for gA,s in hist:
                cnt=tot=0
                for gp in itertools.permutations([x for x in P if x!=gA]):
                    G={A:gA}; G.update(zip(others,gp)); tot+=1
                    cnt+= any(s[G[i]]==R[i] for i in P)
                lik*=cnt/tot
            for gp in itertools.permutations(gpos):
                G={A:g[A]}; G.update(zip(others,gp))
                if any(star[G[i]]==R[i] for i in P): continue
                w+=lik; wm+=lik*(star[G[B]]==R[A])
        stats[round(wm/w,2)]+=1
    return stats
for n in (4,5):
    st=run(n,800); t=sum(st.values())
    print(n, {k:f"{v/t:.0%}" for k,v in sorted(st.items())})
