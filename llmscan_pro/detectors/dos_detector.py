from collections import Counter
def detect_unbounded(text, max_chars=8000):
    L=len(text or '')
    tokens=(text or '').split()
    top=Counter(tokens).most_common(1)
    rep_ratio=(top[0][1]/max(1,len(tokens))) if tokens else 0.0
    score=0.0; hits={}
    if L>max_chars: score+=0.6; hits['length']=L
    if rep_ratio>0.6 and len(tokens)>500: score+=0.4; hits['rep_ratio']=round(rep_ratio,3)
    return {'name':'unbounded','score':min(score,1.0),'hits':hits}
