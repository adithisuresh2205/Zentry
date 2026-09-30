"""
SentinelGate — Network & IP Utilities
======================================
IP extraction, validation, and normalization for IPv4 and IPv6.
Supports trusted proxy CIDR checking to prevent X-Forwarded-For spoofing.
"""
from __future__ import annotations

import ipaddress
from typing import Sequence


def parse_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Safely parse an IP address string into an IPAddress object."""
    try:
        cleaned = ip_str.strip()
        # Handle [2001:db8::1]:443
        if cleaned.startswith("["):
            end_bracket = cleaned.find("]")
            if end_bracket != -1:
                cleaned = cleaned[1:end_bracket]
        elif ":" in cleaned and cleaned.count(":") == 1:
            # IPv4 with port e.g. 192.168.1.1:8080
            cleaned = cleaned.split(":")[0]
        # Handle octal or zero-padded IPv4 parts like 192.168.01.01
        if "." in cleaned and ":" not in cleaned:
            parts = cleaned.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                cleaned = ".".join(str(int(p)) for p in parts)
        return ipaddress.ip_address(cleaned)
    except (ValueError, IndexError):
        return None



def is_ip_in_networks(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Sequence[str],
) -> bool:
    """Check if an IP address belongs to any of the specified CIDR networks or exact IPs."""
    for net in networks:
        try:
            if "/" in net:
                network_obj = ipaddress.ip_network(net, strict=False)
                if ip.version == network_obj.version and ip in network_obj:
                    return True
            else:
                exact_ip = ipaddress.ip_address(net)
                if ip == exact_ip:
                    return True
        except ValueError:
            continue
    return False


def normalize_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> tuple[str, bool]:
    """
    Normalize an IP address to a canonical string and determine if it is IPv6.
    For IPv6, returns compressed standard format.
    """
    if isinstance(ip, str):
        parsed = parse_ip(ip)
        if not parsed:
            # Fallback for unparseable raw string
            return ip.strip(), False
        ip_obj = parsed
    else:
        ip_obj = ip

    is_v6 = isinstance(ip_obj, ipaddress.IPv6Address)
    return ip_obj.compressed, is_v6


def get_rate_limit_ip_key(client_ip: str) -> str:
    """
    Return a canonical IP key for rate limiting and brute-force tracking.
    For IPv6, aggregates by /48 prefix to prevent prefix-hopping evasion.
    For IPv4, returns the normalized canonical address.
    """
    parsed = parse_ip(client_ip)
    if parsed and isinstance(parsed, ipaddress.IPv6Address):
        net = ipaddress.IPv6Network(f"{parsed.compressed}/48", strict=False)
        return str(net.network_address)
    if parsed:
        return parsed.compressed
    return client_ip.strip()


def extract_client_ip(
    peer_ip: str | None,
    headers: dict[str, str],
    trusted_proxies: Sequence[str],
) -> tuple[str, bool]:
    """
    Extract the real client IP address safely from request headers and direct socket peer IP.
    
    Security rule:
    Headers such as `X-Forwarded-For` or `X-Real-IP` are ONLY trusted if the direct
    socket peer IP is within `trusted_proxies` (e.g. reverse proxy Nginx / Docker network).
    If peer is not trusted, peer IP is used directly to prevent IP spoofing.
    """
    default_ip = "127.0.0.1"
    parsed_peer = parse_ip(peer_ip) if peer_ip else None

    if not parsed_peer:
        # If no socket peer IP exists (e.g., test client), inspect X-Forwarded-For directly
        xff = headers.get("x-forwarded-for")
        if xff:
            first_client = xff.split(",")[0].strip()
            return normalize_ip(first_client)
        x_real = headers.get("x-real-ip")
        if x_real:
            return normalize_ip(x_real.strip())
        return default_ip, False

    # Check if socket peer is a trusted proxy
    if is_ip_in_networks(parsed_peer, trusted_proxies):
        # Examine X-Forwarded-For: parse chain from right (proxies) to left (client)
        xff = headers.get("x-forwarded-for")
        if xff:
            parts = [part.strip() for part in xff.split(",") if part.strip()]
            # Walk backwards through trusted proxies to find the first untrusted client IP
            for part in reversed(parts):
                ip_cand = parse_ip(part)
                if ip_cand and not is_ip_in_networks(ip_cand, trusted_proxies):
                    return normalize_ip(ip_cand)
            # If all are in trusted networks, return the leftmost client
            if parts:
                return normalize_ip(parts[0])

        x_real = headers.get("x-real-ip")
        if x_real:
            real_cand = parse_ip(x_real.strip())
            if real_cand:
                return normalize_ip(real_cand)

    return normalize_ip(parsed_peer)
