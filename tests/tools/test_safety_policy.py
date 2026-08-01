import pytest


def test_provenance_labels_external_content_as_untrusted():
    from tools.safety_policy import provenance_label, is_untrusted

    assert provenance_label("https://example.com/a") == "web_content"
    assert provenance_label("/tmp/repo/README.md") == "external_file"
    assert is_untrusted("web_content") is True
    assert is_untrusted("user_instruction") is False


def test_audience_floor_defaults_unknown_to_private():
    from tools.safety_policy import audience_floor

    assert audience_floor([]) == "private"
    assert audience_floor(["private", "shared"]) == "private"
    assert audience_floor(["public", "shared"]) == "shared"
    assert audience_floor(["public", "unknown"]) == "private"


def test_egress_policy_normalizes_hosts_and_denies_subdomains():
    from tools.safety_policy import EgressPolicy, egress_decision

    policy = EgressPolicy(allowed_hosts=("example.com",), denied_hosts=("blocked.example.com",))
    assert egress_decision("api.example.com", policy).allow is True
    denied = egress_decision("x.blocked.example.com", policy)
    assert denied.allow is False
    assert denied.verdict == "denied"


def test_strict_attribution_blocks_degraded_sources():
    from tools.safety_policy import attribution_decision

    assert attribution_decision("direct_human", strict=True).allow is True
    assert attribution_decision("owner_fallback", strict=True).allow is False
    assert attribution_decision("owner_fallback", strict=False).allow is True
    assert attribution_decision("owner_fallback", strict=True).verdict == "imprecise"


def test_egress_policy_rejects_ambiguous_host_rules():
    from tools.safety_policy import parse_egress_policy

    with pytest.raises(ValueError, match="host name"):
        parse_egress_policy({"allowedHosts": ["https://example.com"]})