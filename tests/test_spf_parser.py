from dnsguard.checks.email import parse_spf, parse_dmarc

def test_spf_strict():
    r = parse_spf("v=spf1 -all")
    assert r.policy == "-all"
    assert not any("permissive" in w.lower() for w in r.warnings)

def test_spf_permissive():
    r = parse_spf("v=spf1 +all")
    assert r.policy == "+all"
    assert any("overly permissive" in w.lower() for w in r.warnings)

def test_dmarc_none():
    r = parse_dmarc("v=DMARC1; p=none; rua=mailto:test@example.com")
    assert r.policy == "none"
    assert any("monitoring" in w.lower() for w in r.warnings)
