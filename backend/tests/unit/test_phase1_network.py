"""
Phase 1 — Unit Tests: Network & IP Normalization
=================================================
Tests for IPv4 and IPv6 extraction, normalization, port stripping,
and anti-spoofing logic via trusted proxy networks.
"""
from __future__ import annotations

import pytest

from backend.network import (
    extract_client_ip,
    is_ip_in_networks,
    normalize_ip,
    parse_ip,
)


class TestIPParsingAndNormalization:
    """Tests for IP parsing and normalization helpers."""

    def test_parse_valid_ipv4(self) -> None:
        ip = parse_ip("192.168.1.50")
        assert ip is not None
        assert ip.version == 4

    def test_parse_valid_ipv6(self) -> None:
        ip = parse_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert ip is not None
        assert ip.version == 6

    def test_parse_ipv4_with_port(self) -> None:
        ip = parse_ip("192.168.1.50:8080")
        assert ip is not None
        assert str(ip) == "192.168.1.50"

    def test_parse_ipv6_with_brackets_and_port(self) -> None:
        ip = parse_ip("[2001:db8::1]:443")
        assert ip is not None
        assert str(ip) == "2001:db8::1"

    def test_parse_invalid_ip_returns_none(self) -> None:
        assert parse_ip("invalid-ip") is None
        assert parse_ip("999.999.999.999") is None

    def test_normalize_ip_ipv4(self) -> None:
        normalized, is_v6 = normalize_ip("192.168.01.01")
        assert normalized == "192.168.1.1"
        assert not is_v6

    def test_normalize_ip_ipv6(self) -> None:
        normalized, is_v6 = normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert normalized == "2001:db8::1"
        assert is_v6


class TestTrustedProxyAndAntiSpoofing:
    """Tests for trusted proxy evaluation and real client IP extraction."""

    @pytest.fixture
    def trusted_proxies(self) -> list[str]:
        return ["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12"]

    def test_peer_in_trusted_network(self, trusted_proxies: list[str]) -> None:
        ip = parse_ip("10.0.5.12")
        assert ip is not None
        assert is_ip_in_networks(ip, trusted_proxies) is True

    def test_peer_not_in_trusted_network(self, trusted_proxies: list[str]) -> None:
        ip = parse_ip("203.0.113.195")
        assert ip is not None
        assert is_ip_in_networks(ip, trusted_proxies) is False

    def test_extract_ip_from_untrusted_peer_ignores_xff(
        self, trusted_proxies: list[str]
    ) -> None:
        """
        Anti-spoofing test:
        An untrusted direct peer cannot spoof its IP via X-Forwarded-For.
        """
        headers = {"x-forwarded-for": "8.8.8.8"}
        ip, is_v6 = extract_client_ip(
            peer_ip="203.0.113.195",
            headers=headers,
            trusted_proxies=trusted_proxies,
        )
        assert ip == "203.0.113.195"
        assert not is_v6

    def test_extract_ip_from_trusted_proxy_uses_xff_client(
        self, trusted_proxies: list[str]
    ) -> None:
        """
        Legitimate reverse proxy test:
        When peer is trusted (e.g. 10.0.0.1 Nginx), X-Forwarded-For is trusted.
        """
        headers = {"x-forwarded-for": "198.51.100.42, 10.0.0.1"}
        ip, is_v6 = extract_client_ip(
            peer_ip="10.0.0.1",
            headers=headers,
            trusted_proxies=trusted_proxies,
        )
        assert ip == "198.51.100.42"
        assert not is_v6

    def test_extract_ipv6_client_through_trusted_proxy(
        self, trusted_proxies: list[str]
    ) -> None:
        headers = {"x-forwarded-for": "2001:db8::cafe"}
        ip, is_v6 = extract_client_ip(
            peer_ip="127.0.0.1",
            headers=headers,
            trusted_proxies=trusted_proxies,
        )
        assert ip == "2001:db8::cafe"
        assert is_v6

    def test_extract_ip_without_peer_falls_back_to_headers(
        self, trusted_proxies: list[str]
    ) -> None:
        headers = {"x-forwarded-for": "198.51.100.5"}
        ip, _ = extract_client_ip(
            peer_ip=None,
            headers=headers,
            trusted_proxies=trusted_proxies,
        )
        assert ip == "198.51.100.5"

    def test_extract_ip_fallback_to_real_ip(
        self, trusted_proxies: list[str]
    ) -> None:
        headers = {"x-real-ip": "198.51.100.99"}
        ip, _ = extract_client_ip(
            peer_ip=None,
            headers=headers,
            trusted_proxies=trusted_proxies,
        )
        assert ip == "198.51.100.99"

        # When peer is trusted proxy, x-real-ip also works
        ip2, _ = extract_client_ip(
            peer_ip="127.0.0.1",
            headers={"x-real-ip": "198.51.100.77"},
            trusted_proxies=trusted_proxies,
        )
        assert ip2 == "198.51.100.77"

    def test_extract_ip_all_proxies_trusted_returns_leftmost(
        self, trusted_proxies: list[str]
    ) -> None:
        """When all IPs in chain are in trusted CIDRs, returns leftmost."""
        headers = {"x-forwarded-for": "10.0.0.1, 10.0.0.2"}
        ip, _ = extract_client_ip(
            peer_ip="10.0.0.3",
            headers=headers,
            trusted_proxies=trusted_proxies,
        )
        assert ip == "10.0.0.1"

    def test_extract_ip_no_peer_no_headers_returns_default(
        self, trusted_proxies: list[str]
    ) -> None:
        """When no peer IP and no headers, returns 127.0.0.1."""
        ip, is_v6 = extract_client_ip(
            peer_ip=None,
            headers={},
            trusted_proxies=trusted_proxies,
        )
        assert ip == "127.0.0.1"
        assert not is_v6


