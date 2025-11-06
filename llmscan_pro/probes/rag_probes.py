def _p(id, family, ingest_docs=None, query=None):
    rec = {'id': id, 'family': family}
    if ingest_docs:
        rec['ingest_docs'] = ingest_docs
    if query:
        rec['query'] = query
    return rec

def p_rag_demo():
    return _p(
        'rag.demo.001',
        'rag',
        ingest_docs=[{'id': 'd1', 'text': 'sample text', 'trust': 'trusted'}],
        query='sample query'
    )

PROBES_RAG = [p_rag_demo]
