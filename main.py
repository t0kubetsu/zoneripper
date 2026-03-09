#!/usr/bin/env python3
"""
DNSSEC Zone Walking Tester
Uses dnspython (dns.resolver, dns.query, dns.dnssec) — zero subprocess calls.

Install:
    pip install dnspython

Usage:
    python3 dnssec_zone_walk.py <domain> [--max-steps N] [--nameserver IP]

Examples:
    python3 dnssec_zone_walk.py example.com
    python3 dnssec_zone_walk.py example.com --max-steps 100 --nameserver 8.8.8.8
"""

import argparse
import sys
from typing import Optional

try:
    import dns.dnssec
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.resolver
except ImportError:
    print("Error: dnspython is not installed.")
    print("Run:  pip install dnspython")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# Resolver / transport helpers
# ─────────────────────────────────────────────────────────────


def make_resolver(nameserver: Optional[str] = None) -> dns.resolver.Resolver:
    """Build a Resolver with the DO (DNSSEC OK) bit set."""
    r = dns.resolver.Resolver(configure=True)
    if nameserver:
        r.nameservers = [nameserver]
    # Request DNSSEC records in every query
    r.use_edns(ednsflags=dns.flags.DO, payload=4096)
    return r


def udp_query(
    qname: str,
    rdtype,
    nameserver_ip: str,
    timeout: float = 5.0,
) -> Optional[dns.message.Message]:
    """Send a raw UDP query with DO bit; return the Message or None on error."""
    try:
        name = dns.name.from_text(qname)
        req = dns.message.make_query(name, rdtype, use_edns=True, want_dnssec=True)
        return dns.query.udp(req, nameserver_ip, timeout=timeout)
    except dns.exception.DNSException:
        return None


def resolve_to_ip(hostname: str, resolver: dns.resolver.Resolver) -> Optional[str]:
    """Resolve a hostname to its first A record IP."""
    try:
        ans = resolver.resolve(hostname, "A", raise_on_no_answer=False)
        if ans.rrset:
            return str(list(ans.rrset)[0].address)
    except dns.exception.DNSException:
        pass
    return None


def get_zone_nameserver_ip(
    domain: str, resolver: dns.resolver.Resolver
) -> Optional[str]:
    """Return an IP for the first authoritative NS of *domain*."""
    try:
        ns_ans = resolver.resolve(domain, "NS", raise_on_no_answer=False)
        if ns_ans.rrset:
            for rdata in ns_ans.rrset:
                ip = resolve_to_ip(str(rdata.target), resolver)
                if ip:
                    return ip
    except dns.exception.DNSException:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# DNSSEC status checks
# ─────────────────────────────────────────────────────────────


def check_dnssec_enabled(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """True when at least one DNSKEY record exists at the zone apex."""
    try:
        ans = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        return bool(ans.rrset)
    except dns.exception.DNSException:
        return False


def detect_nsec_type(
    domain: str,
    ns_ip: str,
    timeout: float = 5.0,
) -> str:
    """
    Query a guaranteed non-existent name inside *domain* and inspect the
    authority section of the response for NSEC / NSEC3 records.

    Returns: "NSEC" | "NSEC3" | "UNKNOWN"
    """
    probe = f"_zzzonewalk_probe_99_.{domain}"
    response = udp_query(probe, dns.rdatatype.A, ns_ip, timeout)
    if response is None:
        return "UNKNOWN"

    nsec3_found = any(
        rrset.rdtype == dns.rdatatype.NSEC3 for rrset in response.authority
    )
    if nsec3_found:
        return "NSEC3"

    nsec_found = any(rrset.rdtype == dns.rdatatype.NSEC for rrset in response.authority)
    if nsec_found:
        return "NSEC"

    return "UNKNOWN"


# ─────────────────────────────────────────────────────────────
# NSEC record helpers
# ─────────────────────────────────────────────────────────────


def parse_nsec_types(rdata) -> list[str]:
    """
    Extract the advertised RR type names from an NSEC rdata object.
    Works with dnspython's window-based bitmap representation.
    """
    types: list[str] = []
    try:
        for window_num, bitmap in rdata.windows:
            for byte_idx, byte_val in enumerate(bitmap):
                for bit in range(8):
                    if byte_val & (0x80 >> bit):
                        rdtype_val = window_num * 256 + byte_idx * 8 + bit
                        try:
                            types.append(dns.rdatatype.to_text(rdtype_val))
                        except Exception:
                            types.append(str(rdtype_val))
    except Exception:
        pass
    return types


def get_nsec_record(
    owner: str,
    ns_ip: str,
    timeout: float = 5.0,
) -> tuple[Optional[str], list[str]]:
    """
    Query for the NSEC record at *owner* via a direct UDP query.

    Returns:
        (next_owner_name, [rr_type_strings])
        or (None, []) if no NSEC found.
    """
    response = udp_query(owner, dns.rdatatype.NSEC, ns_ip, timeout)
    if response is None:
        return None, []

    # Check answer section first, then authority
    for section in (response.answer, response.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.NSEC:
                rdata = list(rrset)[0]
                next_name = str(rdata.next).rstrip(".")
                types = parse_nsec_types(rdata)
                return next_name, types

    return None, []


# ─────────────────────────────────────────────────────────────
# Zone walking engine
# ─────────────────────────────────────────────────────────────


def walk_zone(
    domain: str,
    ns_ip: str,
    max_steps: int = 50,
) -> list[dict]:
    """
    Follow the NSEC chain starting at the zone apex.

    Returns a list of {"name": str, "types": [str]} dicts for every
    owner name discovered (excluding the apex itself).
    """
    discovered: list[dict] = []
    seen: set[str] = set()
    current = domain

    print(f"\n  {'Owner':<48} Next →")
    print(f"  {'-' * 48} ------")

    for step in range(max_steps):
        if current in seen:
            print(f"\n  [Loop at '{current}'] — walk complete.")
            break
        seen.add(current)

        next_name, types = get_nsec_record(current, ns_ip)

        if not next_name:
            print(f"  {current:<48} (no NSEC record — stopping)")
            break

        print(f"  {current:<48} {next_name}")

        if current != domain:
            discovered.append({"name": current, "types": types})

        # Full loop back to apex
        if next_name == domain:
            print(f"\n  Returned to zone apex — full loop completed.")
            break

        # Left the zone
        if not (next_name.endswith(f".{domain}") or next_name == domain):
            print(f"\n  Next name '{next_name}' is outside zone — stopping.")
            break

        current = next_name

    else:
        print(f"\n  Reached max-steps limit ({max_steps}).")

    return discovered


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test DNSSEC zone walking vulnerability (uses dnspython, no subprocess)."
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--max-steps",
        type=int,
        default=50,
        metavar="N",
        help="Max NSEC hops to follow (default: 50)",
    )
    parser.add_argument(
        "--nameserver",
        metavar="IP",
        help="Force a specific resolver IP (default: system resolver)",
    )
    args = parser.parse_args()

    domain = args.domain.strip().rstrip(".")
    resolver = make_resolver(args.nameserver)

    SEP = "=" * 60
    print(SEP)
    print("  DNSSEC Zone Walking Tester  —  dnspython")
    print(f"  Target     : {domain}")
    if args.nameserver:
        print(f"  Nameserver : {args.nameserver}")
    print(SEP)

    # ── 1. DNSSEC enabled? ──────────────────────────────────
    print("\n[1] Querying DNSKEY records...")
    if not check_dnssec_enabled(domain, resolver):
        print(f"  ✘  No DNSKEY found — DNSSEC is NOT enabled on '{domain}'.")
        print("     Zone walking requires DNSSEC; nothing to test.")
        sys.exit(0)
    print(f"  ✔  DNSKEY records present — DNSSEC is ENABLED.")

    # ── 2. Resolve authoritative NS ─────────────────────────
    print("\n[2] Resolving authoritative nameserver...")
    ns_ip = get_zone_nameserver_ip(domain, resolver)
    if not ns_ip:
        ns_ip = args.nameserver or resolver.nameservers[0]
        print(f"  (Could not resolve NS; falling back to {ns_ip})")
    else:
        print(f"  ✔  Authoritative NS IP: {ns_ip}")

    # ── 3. NSEC vs NSEC3 ────────────────────────────────────
    print("\n[3] Detecting denial-of-existence mechanism...")
    nsec_type = detect_nsec_type(domain, ns_ip)

    if nsec_type == "NSEC3":
        print("  ✔  NSEC3 detected — NOT vulnerable to zone walking.")
        print("     (Owner names are hashed; enumeration is not directly possible.)")
        print(f"\n  Verdict: {domain} is SAFE.\n{SEP}\n")
        sys.exit(0)
    elif nsec_type == "NSEC":
        print("  ⚠   Plain NSEC detected — potentially VULNERABLE to zone walking!")
    else:
        print("  ?  Could not detect NSEC type — attempting walk anyway...")

    # ── 4. Walk ─────────────────────────────────────────────
    print("\n[4] Attempting NSEC zone walk...")
    discovered = walk_zone(domain, ns_ip, max_steps=args.max_steps)

    # ── 5. Report ────────────────────────────────────────────
    print(f"\n[5] Results")
    print(SEP)
    if discovered:
        print(f"  Enumerated {len(discovered)} name(s):\n")
        print(f"  {'Hostname':<48} RR Types")
        print(f"  {'-' * 48} --------")
        for entry in discovered:
            types_str = ", ".join(entry["types"]) if entry["types"] else "—"
            print(f"  {entry['name']:<48} {types_str}")
        print(
            f"\n  Verdict     : ⚠   VULNERABLE — zone walking succeeded on '{domain}'."
        )
        print(
            "  Remediation : Migrate to NSEC3 (RFC 5155) with opt-out to prevent enumeration."
        )
    else:
        print("  No names enumerated via zone walking.")
        print(f"\n  Verdict: No zone walking exposure detected on '{domain}'.")

    print(SEP)


if __name__ == "__main__":
    main()
