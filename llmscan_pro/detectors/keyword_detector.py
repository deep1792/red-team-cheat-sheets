def detect_keywords(text):
    kws=['secret','password','api_key','system prompt','do not reveal','confidential']
    hits=[k for k in kws if k in (text or '').lower()]
    return {'name':'keyword','score':min(1.0,0.2*len(hits)),'hits':hits}
