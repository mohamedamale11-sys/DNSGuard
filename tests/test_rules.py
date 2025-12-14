from dnsguard.cli import _score_report

def test_scoring_bounds():
    assert _score_report([]) == 100
    s = _score_report(["No DMARC record found.", "CNAME target failed to resolve. potential takeover risk"])
    assert 0 <= s <= 100
