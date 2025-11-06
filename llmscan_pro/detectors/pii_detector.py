import re
def detect_pii(text):
    hits=[]
    if re.search(r'\b\d{3}-\d{2}-\d{4}\b', text or ''): hits.append('ssn')
    if re.search(r'\b\d{10}\b', text or ''): hits.append('phone')
    if re.search(r'\b[\w.-]+@[\w.-]+\.[A-Za-z]{2,}\b', text or ''): hits.append('email')
    return {'name':'pii','score':0.8 if hits else 0.0,'hits':hits}
