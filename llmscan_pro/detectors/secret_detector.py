import re
def detect_secrets(text):
    hits=[]
    for m in re.findall(r'\b[A-Za-z0-9\-]{8,}\b', text or ''):
        if any(c.isdigit() for c in m) and any(c.isalpha() for c in m): hits.append(m)
    return {'name':'secrets','score':0.9 if hits else 0.0,'hits':hits}
