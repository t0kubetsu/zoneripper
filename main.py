#!/usr/bin/env python3
"""
DNSSEC Zone Walking Tester
Uses dnspython (dns.resolver, dns.query, dns.dnssec) — zero subprocess calls.

Install:
    pip install dnspython

Usage (CLI):
    python3 dnssec_zone_walk.py <domain> [--max-steps N] [--nameserver IP]

Usage (module):
    from dnssec_zone_walk import run
    results = run("example.com", max_steps=100, nameserver="8.8.8.8")

Examples:
    python3 dnssec_zone_walk.py example.com
    python3 dnssec_zone_walk.py example.com --max-steps 100 --nameserver 8.8.8.8
"""

import sys
import argparse
import logging
from typing import Optional

try:
    import dns.resolver
    import dns.dnssec
    import dns.query
    import dns.message
    import dns.name
    import dns.rdatatype
    import dns.flags
    import dns.exception
    import dns.rcode
except ImportError:
    logging.critical("dnspython is not installed. Run: pip install dnspython")
    sys.exit(1)

log = logging.getLogger(__name__)


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


def is_valid_hostname_label(label: str) -> bool:
    """
    Return True if a DNS label looks like a real hostname component.
    Rejects labels containing null bytes, non-printable characters,
    or other synthetic patterns injected by some nameservers to
    trap zone walkers (e.g. \\000, \\001, ...).
    """
    if not label:
        return False
    # Null-byte / escape sequences used by trap nameservers
    if "\\000" in label or "\x00" in label:
        return False
    # Allow only printable ASCII that is valid in a hostname label
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.*")
    return all(c in allowed for c in label)


def is_valid_zone_name(name: str, domain: str) -> bool:
    """
    Return True if *name* is a plausible real owner name inside *domain*.
    Strips the domain suffix and validates every remaining label.
    """
    if name == domain:
        return True
    suffix = f".{domain}"
    if not name.endswith(suffix):
        return False
    subdomain = name[: -len(suffix)]  # e.g. "www" or "mail.sub"
    return all(is_valid_hostname_label(lbl) for lbl in subdomain.split("."))


def walk_zone(
    domain: str,
    ns_ip: str,
    max_steps: int = 50,
) -> list[dict]:
    """
    Follow the NSEC chain starting at the zone apex.

    Skips synthetic / trap names (e.g. \\000.\\000...) that some
    nameservers return to stall automated walkers.

    Returns a list of {"name": str, "types": [str]} dicts for every
    real owner name discovered (excluding the apex itself).
    """
    discovered: list[dict] = []
    seen: set[str] = set()
    current = domain
    trap_streak = 0  # consecutive invalid names
    MAX_TRAP_STREAK = 3  # abort after this many in a row

    log.debug("%-48s  %s", "Owner", "Next →")
    log.debug("%s  %s", "-" * 48, "------")

    for step in range(max_steps):
        if current in seen:
            log.info("Loop detected at '%s' — walk complete.", current)
            break
        seen.add(current)

        next_name, types = get_nsec_record(current, ns_ip)

        if not next_name:
            log.info("%-48s  (no NSEC record — stopping)", current)
            break

        # ── Trap / synthetic name detection ──────────────────
        if not is_valid_zone_name(next_name, domain):
            trap_streak += 1
            log.warning("%-48s  synthetic next='%s' (skipping)", current, next_name)
            if trap_streak >= MAX_TRAP_STREAK:
                log.warning(
                    "Detected trap pattern (%d consecutive synthetic names) — aborting walk.",
                    trap_streak,
                )
                break
            # Jump past the trap: query the synthetic name directly
            # to get its NSEC and hopefully land back on a real name.
            current = next_name
            continue

        trap_streak = 0  # reset on a valid name

        log.info("%-48s  %s", current, next_name)

        if current != domain and is_valid_zone_name(current, domain):
            discovered.append({"name": current, "types": types})

        # Full loop back to apex
        if next_name == domain:
            log.info("Returned to zone apex — full loop completed.")
            break

        # Left the zone
        if not (next_name.endswith(f".{domain}") or next_name == domain):
            log.info("Next name '%s' is outside zone — stopping.", next_name)
            break

        current = next_name

    else:
        log.warning("Reached max-steps limit (%d).", max_steps)

    return discovered


# ─────────────────────────────────────────────────────────────
# Public API (importable as a module)
# ─────────────────────────────────────────────────────────────


def run(
    domain: str,
    max_steps: int = 50,
    nameserver: Optional[str] = None,
) -> list[dict]:
    """
    Run a full DNSSEC zone-walking test against *domain*.

    Parameters
    ----------
    domain      : Zone apex to test (e.g. "example.com").
    max_steps   : Maximum NSEC hops to follow.
    nameserver  : Optional resolver IP; uses the system resolver when None.

    Returns
    -------
    List of {"name": str, "types": [str]} dicts for every real owner
    name discovered, or an empty list when the zone is not walkable.
    """
    domain = domain.strip().rstrip(".")
    resolver = make_resolver(nameserver)

    SEP = "=" * 60
    log.info(SEP)
    log.info("DNSSEC Zone Walking Tester  —  dnspython")
    log.info("Target     : %s", domain)
    if nameserver:
        log.info("Nameserver : %s", nameserver)
    log.info(SEP)

    # ── 1. DNSSEC enabled? ──────────────────────────────────
    log.info("[1] Querying DNSKEY records...")
    if not check_dnssec_enabled(domain, resolver):
        log.warning("No DNSKEY found — DNSSEC is NOT enabled on '%s'.", domain)
        log.warning("Zone walking requires DNSSEC; nothing to test.")
        return []
    log.info("DNSKEY records present — DNSSEC is ENABLED.")

    # ── 2. Resolve authoritative NS ─────────────────────────
    log.info("[2] Resolving authoritative nameserver...")
    ns_ip = get_zone_nameserver_ip(domain, resolver)
    if not ns_ip:
        ns_ip = nameserver or resolver.nameservers[0]
        log.warning("Could not resolve NS; falling back to %s", ns_ip)
    else:
        log.info("Authoritative NS IP: %s", ns_ip)

    # ── 3. NSEC vs NSEC3 ────────────────────────────────────
    log.info("[3] Detecting denial-of-existence mechanism...")
    nsec_type = detect_nsec_type(domain, ns_ip)

    if nsec_type == "NSEC3":
        log.info("NSEC3 detected — NOT vulnerable to zone walking.")
        log.info("Owner names are hashed; enumeration is not directly possible.")
        log.info("Verdict: %s is SAFE.", domain)
        return []
    elif nsec_type == "NSEC":
        log.warning("Plain NSEC detected — potentially VULNERABLE to zone walking!")
    else:
        log.warning("Could not detect NSEC type — attempting walk anyway...")

    # ── 4. Walk ─────────────────────────────────────────────
    log.info("[4] Attempting NSEC zone walk...")
    discovered = walk_zone(domain, ns_ip, max_steps=max_steps)

    # ── 5. Report ────────────────────────────────────────────
    log.info("[5] Results")
    log.info(SEP)
    if discovered:
        log.info("Enumerated %d name(s):", len(discovered))
        log.info("%-48s  RR Types", "Hostname")
        log.info("%s  %s", "-" * 48, "--------")
        for entry in discovered:
            types_str = ", ".join(entry["types"]) if entry["types"] else "—"
            log.info("%-48s  %s", entry["name"], types_str)
        log.warning("Verdict: VULNERABLE — zone walking succeeded on '%s'.", domain)
        log.warning(
            "Remediation: Migrate to NSEC3 (RFC 5155) with opt-out to prevent enumeration."
        )
    else:
        log.info("No names enumerated via zone walking.")
        log.info("Verdict: No zone walking exposure detected on '%s'.", domain)

    log.info(SEP)
    return discovered


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Build and return parsed CLI arguments (separated for testability)."""
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
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point — parses arguments and delegates to run()."""
    args = parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)-8s %(message)s",
    )

    run(
        domain=args.domain,
        max_steps=args.max_steps,
        nameserver=args.nameserver,
    )


if __name__ == "__main__":
    main()
