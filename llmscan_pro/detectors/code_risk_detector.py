def detect_code_risk(text):
    hits=[]
    if 'rm -rf' in (text or '') or ('curl ' in (text or '') and '| bash' in (text or '')): hits.append('dangerous_shell')
    return {'name':'code_risk','score':0.9 if hits else 0.0,'hits':hits}
