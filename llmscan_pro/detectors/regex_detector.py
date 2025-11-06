import re
def detect_regex(text):
    hits=[]
    if re.search(r'\b[A-Za-z0-9_]{20,}\b', text or ''): hits.append('long_token_like')
    if re.search(r'\b\d{10,}\b', text or ''): hits.append('long_number')
    return {'name':'regex','score':0.6 if hits else 0.0,'hits':hits}
