import re
def detect_hidden_text(text):
    hits=[]
    if re.search(r'<!--.*?-->', text or '', flags=re.S): hits.append('html_comment')
    if '\u200b' in (text or ''): hits.append('zero_width')
    if re.search(r'display\s*:\s*none', text or '', flags=re.I): hits.append('css_display_none')
    return {'name':'hidden','score':0.9 if hits else 0.0,'hits':hits}
