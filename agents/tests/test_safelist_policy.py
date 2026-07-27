"""Unit tests for the shared never-block SafelistPolicy (EPIC-3 #106)."""

from __future__ import annotations

from btagent_shared.security.safelist import (
    BASELINE_SAFELIST,
    SafelistPolicy,
    is_structurally_reserved_ip,
)


def test_baseline_public_resolver_and_private_ips():
    assert BASELINE_SAFELIST.ip_safelisted("8.8.8.8") is True
    assert BASELINE_SAFELIST.ip_safelisted("10.1.2.3") is True  # RFC1918 structural
    assert BASELINE_SAFELIST.ip_safelisted("127.0.0.1") is True  # loopback
    assert BASELINE_SAFELIST.ip_safelisted("185.220.101.42") is False  # public, blockable


def test_baseline_critical_domain_suffix_match():
    assert BASELINE_SAFELIST.domain_safelisted("login.microsoftonline.office.com") is True
    assert BASELINE_SAFELIST.domain_safelisted("office.com") is True
    assert BASELINE_SAFELIST.domain_safelisted("evil.example") is False


def test_structural_reserved_helper():
    assert is_structurally_reserved_ip("192.168.1.1") is True
    assert is_structurally_reserved_ip("169.254.0.1") is True  # link-local
    assert is_structurally_reserved_ip("8.8.8.8") is False
    assert is_structurally_reserved_ip("not-an-ip") is False  # malformed → not reserved


def test_merge_layers_org_entries_on_baseline():
    policy = BASELINE_SAFELIST.merge(
        extra_ips=["45.83.12.7"], extra_domain_suffixes=["corp.example"]
    )
    # Org entries now safelisted...
    assert policy.ip_safelisted("45.83.12.7") is True
    assert policy.domain_safelisted("vpn.corp.example") is True
    # ...without dropping the baseline.
    assert policy.ip_safelisted("8.8.8.8") is True
    # Baseline itself is unchanged (merge returns a new policy).
    assert BASELINE_SAFELIST.ip_safelisted("45.83.12.7") is False


def test_domain_matching_is_case_insensitive_and_suffix_bounded():
    policy = SafelistPolicy(domain_suffixes=("corp.example",))
    assert policy.domain_safelisted("VPN.CORP.EXAMPLE") is True
    assert policy.domain_safelisted("corp.example") is True
    # Must be a real suffix boundary — "notcorp.example" must NOT match.
    assert policy.domain_safelisted("notcorp.example") is False


def test_url_safelist_screens_host():
    policy = SafelistPolicy(domain_suffixes=("corp.example",))
    assert policy.url_safelisted("https://vpn.corp.example/login?x=1") is True
    assert policy.url_safelisted("https://evil.example/payload") is False
