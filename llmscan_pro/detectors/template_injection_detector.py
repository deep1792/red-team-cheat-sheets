import re

def detect_template_injection(text, markers=None):
    """
    Detects user-controlled markers leaked into a system/template context.
    Scores higher when markers + 'SYSTEM:' (or 'template:'/'schema:') appear.
    """
    text = text or ""
    markers = markers or ["PASTE_SECRET=abc123", "{{user_input}}"]

    hits = [m for m in markers if m in text]
    score = 0.0
    if hits:
        score = 0.6
        if re.search(r'(?i)(system|template|schema)\s*[:\-]', text):
            score = 0.9
    return {"name": "template_injection", "score": score, "hits": hits}
