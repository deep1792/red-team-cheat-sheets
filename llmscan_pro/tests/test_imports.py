def test_imports():
    import llmscan_pro
    from llmscan_pro.runner import Runner, SUITES
    assert "owasp2025" in SUITES
