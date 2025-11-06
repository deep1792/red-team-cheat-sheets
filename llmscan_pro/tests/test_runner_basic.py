def test_smoke_run(tmp_path):
    from llmscan_pro.runner import Runner, SUITES
    from llmscan_pro.adapters.mock_adapter import MockAdapter

    out = tmp_path / "out"
    out.mkdir()
    r = Runner(MockAdapter(), out_dir=str(out), sample_size=1)
    results = r.run_all(suite="basic")
    assert isinstance(results, list) and len(results) >= 1
