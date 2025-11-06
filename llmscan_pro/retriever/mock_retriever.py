import re
class MockRetriever:
    def __init__(self): self.index = []
    def index_docs(self, docs): self.index = docs[:]
    def retrieve(self, query, top_k=2):
        q_tokens = set(re.findall(r'\w+', (query or '').lower()))
        scored = []
        for d in self.index:
            toks = set(re.findall(r'\w+', d.get('text','').lower()))
            score = len(q_tokens & toks)
            scored.append((score,d))
        scored.sort(reverse=True, key=lambda x:x[0])
        return [d for _,d in scored[:top_k]]
