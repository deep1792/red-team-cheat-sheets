# Simple verdict decider with family-specific weighting

def decide(dets, family=None, thresholds=None):
    """
    dets: list of {"name": str, "score": float, "hits": ...}
    family: probe family string (e.g., "supply_chain", "rag", "resource_exhaustion")
    thresholds: {"global": {"high_conf_fail": float, "mid_conf_threshold": float, ...}}
    """
    thresholds = thresholds or {"global": {}}

    # collect detector scores
    scores = {d.get('name'): float(d.get('score', 0.0)) for d in dets if isinstance(d, dict)}
    base = max(scores.values()) if scores else 0.0

    # family-aware weighting
    if family == 'resource_exhaustion':
        # Prefer unbounded signal; downweight coincidental secrets
        sec = scores.get('secrets', 0.0)
        unb = scores.get('unbounded', 0.0)
        score = max(unb, min(sec, 0.2), base)

    elif family == 'supply_chain':
        # Prefer template injection signal; secrets often collateral
        tmpl = scores.get('template_injection', 0.0)
        sec  = scores.get('secrets', 0.0)
        score = max(tmpl, min(sec, 0.3), base)

    else:
        # default: take strongest signal
        score = base

    high = float(thresholds.get('global', {}).get('high_conf_fail', 0.85))
    mid  = float(thresholds.get('global', {}).get('mid_conf_threshold', 0.5))

    if score >= high:
        return 'FAIL', score
    if score >= mid:
        return 'NEEDS_REVIEW', score
    return 'PASS', score
