#!/usr/bin/env python3
"""
DNSSEC Zone Walking Tester

Install:
    pip install dnspython

Usage (CLI):
    python3 dnssec_zone_walk.py <domain> [options]

Usage (module):
    from dnssec_zone_walk import run
    results = run("example.com", max_steps=100, nameserver="8.8.8.8")

Examples:
    python3 dnssec_zone_walk.py example.com
    python3 dnssec_zone_walk.py example.com --max-steps 100 --nameserver 8.8.8.8
    python3 dnssec_zone_walk.py example.com --wordlist words.txt
"""

import argparse
import base64
import hashlib
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
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
    logging.critical("dnspython is not installed. Run: pip install dnspython")
    sys.exit(1)

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────


@dataclass
class Nsec3Params:
    """NSEC3 algorithm parameters extracted from a zone."""

    algorithm: int  # 1 = SHA-1 (only algorithm defined in RFC 5155)
    flags: int  # 1 = opt-out
    iterations: int  # extra hash rounds (0-2500)
    salt: bytes  # raw salt bytes (may be empty)
    salt_hex: str  # hex-encoded salt or "-" for empty


@dataclass
class Nsec3Hash:
    """A single (owner_hash, next_hash) pair from an NSEC3 record."""

    owner_b32: str  # base32-encoded owner hash (from DNS name label)
    next_b32: str  # base32-encoded next hash
    types: list[str]  # RR types present at this name
    source_ns: str  # which NS returned this record


@dataclass
class Nsec3WalkResult:
    """Aggregated result of an NSEC3 enumeration pass."""

    params: Optional[Nsec3Params]
    hashes: list[Nsec3Hash] = field(default_factory=list)
    cracked: dict[str, str] = field(default_factory=dict)  # hash_b32 -> plaintext


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


def get_zone_nameserver_ips(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    """
    Return IPs for ALL authoritative NS records of *domain*.

    Large TLDs (e.g. .se, .com) run anycast clusters where individual nodes
    may rate-limit or drop NSEC queries differently. Returning all IPs lets
    the caller retry across the full set rather than trusting a single node.
    """
    ips: list[str] = []
    try:
        ns_ans = resolver.resolve(domain, "NS", raise_on_no_answer=False)
        if ns_ans.rrset:
            for rdata in ns_ans.rrset:
                ip = resolve_to_ip(str(rdata.target), resolver)
                if ip and ip not in ips:
                    ips.append(ip)
    except dns.exception.DNSException:
        pass
    return ips


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
    Extract the advertised RR type names from an NSEC/NSEC3 rdata object.
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
    ns_ips: list[str],
    timeout: float = 5.0,
) -> tuple[Optional[str], list[str]]:
    """
    Query for the NSEC record at *owner*, trying each NS IP in turn.

    Some anycast nodes silently drop NSEC queries; rotating through all
    known NS IPs makes the walk resilient to per-node rate-limiting.

    Returns:
        (next_owner_name, [rr_type_strings])
        or (None, []) if no NSEC found on any nameserver.
    """
    for ns_ip in ns_ips:
        response = udp_query(owner, dns.rdatatype.NSEC, ns_ip, timeout)
        if response is None:
            log.debug("No response from %s for NSEC %s — trying next NS", ns_ip, owner)
            continue

        # Check answer section first, then authority
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    rdata = list(rrset)[0]
                    next_name = str(rdata.next).rstrip(".")
                    types = parse_nsec_types(rdata)
                    log.debug("NSEC record obtained from %s for %s", ns_ip, owner)
                    return next_name, types

        log.debug("NS %s returned no NSEC for %s — trying next NS", ns_ip, owner)

    return None, []


# ─────────────────────────────────────────────────────────────
# NSEC zone walking engine
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
    subdomain = name[: -len(suffix)]
    return all(is_valid_hostname_label(lbl) for lbl in subdomain.split("."))


def walk_zone(
    domain: str,
    ns_ips: list[str],
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

    log.debug("%-48s  %s", "Owner", "Next ->")
    log.debug("%s  %s", "-" * 48, "------")

    for step in range(max_steps):
        if current in seen:
            log.info("Loop detected at '%s' - walk complete.", current)
            break
        seen.add(current)

        next_name, types = get_nsec_record(current, ns_ips)

        if not next_name:
            log.info("%-48s  (no NSEC record - stopping)", current)
            break

        # ── Trap / synthetic name detection ──────────────────
        if not is_valid_zone_name(next_name, domain):
            trap_streak += 1
            log.warning("%-48s  synthetic next='%s' (skipping)", current, next_name)
            if trap_streak >= MAX_TRAP_STREAK:
                log.warning(
                    "Detected trap pattern (%d consecutive synthetic names) - aborting walk.",
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
            log.info("Returned to zone apex - full loop completed.")
            break

        # Left the zone
        if not (next_name.endswith(f".{domain}") or next_name == domain):
            log.info("Next name '%s' is outside zone - stopping.", next_name)
            break

        current = next_name

    else:
        log.warning("Reached max-steps limit (%d).", max_steps)

    return discovered


# ─────────────────────────────────────────────────────────────
# NSEC3 - hash collection
# ─────────────────────────────────────────────────────────────


def _extract_nsec3_params(rdata) -> Optional[Nsec3Params]:
    """Extract NSEC3 algorithm parameters from an rdata object."""
    try:
        salt_bytes = rdata.salt if rdata.salt else b""
        return Nsec3Params(
            algorithm=rdata.algorithm,
            flags=rdata.flags,
            iterations=rdata.iterations,
            salt=salt_bytes,
            salt_hex=salt_bytes.hex() if salt_bytes else "-",
        )
    except Exception:
        return None


def _parse_nsec3_rdata(rdata, owner_label: str, ns_ip: str) -> Optional[Nsec3Hash]:
    """
    Extract an Nsec3Hash from a single NSEC3 rdata object.

    dnspython exposes NSEC3 rdata with attributes:
        .algorithm  .flags  .iterations  .salt  .next  .windows
    The owner label is the first label of the owner name (the hash itself),
    already in base32 uppercase as it appears in the DNS wire format.
    The .next field is the raw bytes of the next owner hash.
    """
    try:
        owner_b32 = owner_label.upper()
        next_b32 = _bytes_to_b32hex(rdata.next)
        types = parse_nsec_types(rdata)
        return Nsec3Hash(
            owner_b32=owner_b32,
            next_b32=next_b32,
            types=types,
            source_ns=ns_ip,
        )
    except Exception as exc:
        log.debug("Failed to parse NSEC3 rdata: %s", exc)
        return None


def collect_nsec3_hashes(
    domain: str,
    ns_ips: list[str],
    rounds: int = 30,
    timeout: float = 5.0,
) -> Nsec3WalkResult:
    """
    Collect NSEC3 hashes by repeatedly querying random non-existent subdomains.

    Each NXDOMAIN response returns up to 3 NSEC3 records covering the
    "closest encloser", "next closer", and "wildcard" proofs. Each record
    reveals two hashed names (owner + next). After *rounds* probes we have
    good coverage of the zone's hash space.

    Returns an Nsec3WalkResult with all unique hashes collected.
    """
    result = Nsec3WalkResult(params=None)
    seen_owners: set[str] = set()

    log.info("Collecting NSEC3 hashes via %d random probes...", rounds)

    for i in range(rounds):
        probe_label = uuid.uuid4().hex[:16]
        probe = f"{probe_label}.{domain}"

        for ns_ip in ns_ips:
            response = udp_query(probe, dns.rdatatype.A, ns_ip, timeout)
            if response is None:
                continue

            got_nsec3 = False
            for rrset in response.authority:
                if rrset.rdtype != dns.rdatatype.NSEC3:
                    continue
                got_nsec3 = True

                for rdata in rrset:
                    if result.params is None:
                        result.params = _extract_nsec3_params(rdata)
                        if result.params:
                            log.info(
                                "NSEC3 params - algorithm: %d, iterations: %d, salt: %s",
                                result.params.algorithm,
                                result.params.iterations,
                                result.params.salt_hex,
                            )

                    owner_label = str(rrset.name).split(".")[0].upper()
                    if owner_label in seen_owners:
                        continue
                    seen_owners.add(owner_label)

                    h = _parse_nsec3_rdata(rdata, owner_label, ns_ip)
                    if h:
                        result.hashes.append(h)
                        log.debug(
                            "  [%3d] owner=%-36s  next=%s  types=%s",
                            len(result.hashes),
                            h.owner_b32,
                            h.next_b32,
                            ",".join(h.types),
                        )

            if got_nsec3:
                break

        if (i + 1) % 10 == 0:
            log.info(
                "  probe %d/%d - %d unique hashes so far",
                i + 1,
                rounds,
                len(result.hashes),
            )

    log.info("Collected %d unique NSEC3 hashes.", len(result.hashes))
    return result


# ─────────────────────────────────────────────────────────────
# NSEC3 - hash cracking (pure Python SHA-1, RFC 5155 §5)
# ─────────────────────────────────────────────────────────────

# DNS NSEC3 uses base32hex (RFC 4648 §7) with alphabet 0-9 A-V,
# NOT standard base32 (A-Z 2-7). Python's base64 module only speaks
# standard base32, so we must translate alphabets before encoding/decoding.
_B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_B32STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_TO_STD = str.maketrans(_B32HEX, _B32STD)  # base32hex -> standard
_TO_B32HEX = str.maketrans(_B32STD, _B32HEX)  # standard  -> base32hex


def _bytes_to_b32hex(raw: bytes) -> str:
    """Encode raw bytes as base32hex (RFC 4648 §7), uppercase, no padding."""
    return base64.b32encode(raw).decode().rstrip("=").upper().translate(_TO_B32HEX)


def _b32hex_to_bytes(b32hex: str) -> bytes:
    """Decode a base32hex string (as found in DNS NSEC3 owner labels) to raw bytes."""
    padded = b32hex.upper().translate(_TO_STD) + "=" * (-len(b32hex) % 8)
    return base64.b32decode(padded)


def _b32hex_to_hex(b32hex: str) -> str:
    """Convert a base32hex hash label to lowercase hex."""
    return _b32hex_to_bytes(b32hex).hex()


def _hash_to_b32hex(raw: bytes) -> str:
    """Encode a raw SHA-1 digest as base32hex for comparison against DNS labels."""
    return _bytes_to_b32hex(raw)


def _is_valid_dns_label(label: str) -> bool:
    """
    Return True if *label* is a valid DNS label that can be hashed.

    RFC 1035 limits each label to 63 octets max. Wordlists like rockyou
    contain entries that exceed this or contain non-encodable characters,
    which would cause a ValueError when building the wire-format name.
    """
    try:
        encoded = label.lower().encode()
        return 1 <= len(encoded) <= 63
    except (UnicodeEncodeError, UnicodeDecodeError):
        return False


def _nsec3_hash(label: str, domain: str, salt: bytes, iterations: int) -> bytes:
    """
    Compute the NSEC3 hash for a candidate label as defined in RFC 5155 §5.

    IH(salt, x, 0) = H(x || salt)
    IH(salt, x, k) = H(IH(salt, x, k-1) || salt)   for k > 0

    where H = SHA-1 and x is the wire-format fully-qualified owner name
    with all labels lowercased.

    Raises ValueError for labels that exceed 63 octets (invalid DNS label).
    """
    fqdn = f"{label.lower()}.{domain.lower()}."
    wire = b""
    for part in fqdn.rstrip(".").split("."):
        encoded = part.encode()
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long ({len(encoded)} bytes): {part!r}")
        wire += bytes([len(encoded)]) + encoded
    wire += b"\x00"

    digest = hashlib.sha1(wire + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return digest


def crack_nsec3_hashes(
    result: Nsec3WalkResult,
    domain: str,
    wordlist: list[str],
) -> dict[str, str]:
    """
    Attempt to reverse NSEC3 hashes via dictionary attack (pure Python).

    For each candidate word in *wordlist*, computes NSEC3(word + "." + domain)
    using the zone's own salt and iteration count, then checks against all
    collected hashes. Matches reveal real subdomain names.

    Invalid candidates (label > 63 bytes, non-encodable chars) are silently
    skipped — this makes large wordlists like rockyou safe to use directly.

    Returns a dict mapping owner_b32 -> cracked plaintext label.
    """
    if result.params is None:
        log.warning("No NSEC3 params available - cannot crack.")
        return {}

    if result.params.algorithm != 1:
        log.warning(
            "NSEC3 algorithm %d is not SHA-1 - pure-Python cracking not supported.",
            result.params.algorithm,
        )
        return {}

    salt = result.params.salt
    iterations = result.params.iterations

    target_hashes: dict[str, Nsec3Hash] = {h.owner_b32: h for h in result.hashes}
    if not target_hashes:
        return {}

    log.info(
        "Cracking %d NSEC3 hashes (salt=%s, iterations=%d) against %d candidates...",
        len(target_hashes),
        result.params.salt_hex,
        iterations,
        len(wordlist),
    )

    cracked: dict[str, str] = {}
    skipped = 0
    for candidate in wordlist:
        if not _is_valid_dns_label(candidate):
            skipped += 1
            continue
        try:
            raw = _nsec3_hash(candidate, domain, salt, iterations)
        except (ValueError, UnicodeEncodeError):
            skipped += 1
            continue
        b32 = _hash_to_b32hex(raw)
        if b32 in target_hashes and b32 not in cracked:
            cracked[b32] = candidate
            log.info("  CRACKED: %s  ->  %s.%s", b32, candidate, domain)

    if skipped:
        log.debug("Skipped %d invalid/oversized candidates.", skipped)
    log.info("Cracked %d / %d hashes.", len(cracked), len(target_hashes))
    result.cracked = cracked
    return cracked


def export_hashcat_file(
    result: Nsec3WalkResult,
    domain: str,
    path: str,
    uncracked_only: bool = False,
) -> None:
    """
    Write NSEC3 hashes in hashcat mode 8300 format:

        <hash_b32hex_lower>:<.zone>:<salt_hex>:<iterations>

    Example for domain "sh", salt "73", 0 iterations:
        9clkef9t1cpn5jp5ltaohtp49dqi9foj:.sh:73:0

    Parameters
    ----------
    uncracked_only : When True, only export hashes that were not cracked.
                     Used to continue cracking offline with a bigger wordlist.

    Crack offline with:
        hashcat -m 8300 <file> <wordlist> --keep-guessing
    """
    if not result.hashes or result.params is None:
        log.warning("Nothing to export.")
        return

    salt_hex = result.params.salt_hex if result.params.salt_hex != "-" else ""
    zone = f".{domain}"
    count = 0
    with open(path, "w") as f:
        for h in result.hashes:
            if uncracked_only and h.owner_b32 in result.cracked:
                continue
            f.write(
                f"{h.owner_b32.lower()}:{zone}:{salt_hex}:{result.params.iterations}\n"
            )
            count += 1

    label = "uncracked " if uncracked_only else ""
    log.info("Exported %d %shashes to '%s' (hashcat -m 8300)", count, label, path)
    log.info("Run: hashcat -m 8300 --keep-guessing %s <wordlist>", path)


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────


def run(
    domain: str,
    max_steps: int = 50,
    nameserver: Optional[str] = None,
    nsec3_rounds: int = 30,
    wordlist: Optional[list[str]] = None,
) -> dict:
    """
    Run a full DNSSEC zone-walking test against *domain*.

    For NSEC zones  -> follows the NSEC chain and returns discovered names.
    For NSEC3 zones -> collects hashes, then:
        - If wordlist provided: attempts cracking, writes uncracked hashes to
          <domain>_nsec3.hashes for offline GPU cracking.
        - If no wordlist:       writes all hashes to <domain>_nsec3.hashes.

    Parameters
    ----------
    domain       : Zone apex to test (e.g. "example.com").
    max_steps    : Maximum NSEC hops to follow.
    nameserver   : Optional resolver IP; uses the system resolver when None.
    nsec3_rounds : Number of random probes for NSEC3 hash collection.
    wordlist     : List of candidate labels for NSEC3 cracking. When None,
                   skips cracking and writes all hashes to the output file.

    Returns
    -------
    dict with keys:
        "nsec_type"   : "NSEC" | "NSEC3" | "UNKNOWN" | "NONE"
        "nsec_names"  : list[dict]        -- discovered names (NSEC path)
        "nsec3"       : Nsec3WalkResult | None
    """
    domain = domain.strip().rstrip(".")
    resolver = make_resolver(nameserver)

    SEP = "=" * 60
    log.info(SEP)
    log.info("DNSSEC Zone Walking Tester")
    log.info("Target     : %s", domain)
    if nameserver:
        log.info("Nameserver : %s", nameserver)
    log.info(SEP)

    # -- 1. DNSSEC enabled? --------------------------------------
    log.info("[1] Querying DNSKEY records...")
    if not check_dnssec_enabled(domain, resolver):
        log.warning("No DNSKEY found - DNSSEC is NOT enabled on '%s'.", domain)
        log.warning("Zone walking requires DNSSEC; nothing to test.")
        return {"nsec_type": "NONE", "nsec_names": [], "nsec3": None}
    log.info("DNSKEY records present - DNSSEC is ENABLED.")

    # -- 2. Resolve authoritative NS -----------------------------
    log.info("[2] Resolving authoritative nameservers...")
    ns_ips = get_zone_nameserver_ips(domain, resolver)
    if not ns_ips:
        fallback = nameserver or resolver.nameservers[0]
        log.warning("Could not resolve any NS; falling back to %s", fallback)
        ns_ips = [fallback]
    else:
        log.info("Authoritative NS IPs: %s", ", ".join(ns_ips))

    # -- 3. NSEC vs NSEC3 ----------------------------------------
    log.info("[3] Detecting denial-of-existence mechanism...")
    nsec_type = detect_nsec_type(domain, ns_ips[0])

    # -- 4a. NSEC walk -------------------------------------------
    if nsec_type == "NSEC":
        log.warning("Plain NSEC detected - potentially VULNERABLE to zone walking!")
        log.info("[4] Attempting NSEC zone walk...")
        discovered = walk_zone(domain, ns_ips, max_steps=max_steps)

        log.info("[5] Results")
        log.info(SEP)
        if discovered:
            log.info("Enumerated %d name(s):", len(discovered))
            log.info("%-48s  RR Types", "Hostname")
            log.info("%s  %s", "-" * 48, "--------")
            for entry in discovered:
                types_str = ", ".join(entry["types"]) if entry["types"] else "-"
                log.info("%-48s  %s", entry["name"], types_str)
            log.warning("Verdict: VULNERABLE - zone walking succeeded on '%s'.", domain)
            log.warning("Remediation: Migrate to NSEC3 (RFC 5155) with opt-out.")
        else:
            log.info("No names enumerated via zone walking.")
            log.info("Verdict: No zone walking exposure detected on '%s'.", domain)
        log.info(SEP)

        return {"nsec_type": "NSEC", "nsec_names": discovered, "nsec3": None}

    # -- 4b. NSEC3 hash collection + cracking --------------------
    elif nsec_type == "NSEC3":
        log.info("NSEC3 detected - collecting hashes...")
        log.info("[4] Collecting NSEC3 hashes via %d random probes...", nsec3_rounds)

        nsec3_result = collect_nsec3_hashes(domain, ns_ips, rounds=nsec3_rounds)
        export_path = f"{domain}_nsec3.hashes"

        if wordlist:
            # Wordlist provided: crack, then write only uncracked hashes
            log.info("[5] Attempting dictionary crack of NSEC3 hashes...")
            crack_nsec3_hashes(nsec3_result, domain, wordlist=wordlist)

            log.info("[6] Results")
            log.info(SEP)
            log.info("Collected %d unique NSEC3 hashes.", len(nsec3_result.hashes))

            if nsec3_result.cracked:
                log.warning(
                    "Cracked %d / %d hash(es):",
                    len(nsec3_result.cracked),
                    len(nsec3_result.hashes),
                )
                for b32, label in nsec3_result.cracked.items():
                    log.warning("  %s  ->  %s.%s", b32, label, domain)

            uncracked_count = len(nsec3_result.hashes) - len(nsec3_result.cracked)
            if uncracked_count > 0:
                export_hashcat_file(
                    nsec3_result, domain, export_path, uncracked_only=True
                )
            else:
                log.info("All hashes cracked - no output file written.")

            if nsec3_result.cracked:
                log.warning(
                    "Verdict: NSEC3 hashes partially reversed - subdomain names exposed."
                )
        else:
            # No wordlist: write all hashes for offline cracking
            log.info(
                "[5] No wordlist provided - writing all hashes for offline cracking."
            )
            log.info("[6] Results")
            log.info(SEP)
            log.info("Collected %d unique NSEC3 hashes.", len(nsec3_result.hashes))
            export_hashcat_file(nsec3_result, domain, export_path, uncracked_only=False)

        log.info(SEP)
        return {"nsec_type": "NSEC3", "nsec_names": [], "nsec3": nsec3_result}

    # -- Unknown -------------------------------------------------
    else:
        log.warning("Could not detect NSEC type for '%s'.", domain)
        return {"nsec_type": "UNKNOWN", "nsec_names": [], "nsec3": None}


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Build and return parsed CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Test DNSSEC zone walking vulnerability.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--max-steps",
        type=int,
        default=50,
        metavar="N",
        help="Max NSEC hops to follow",
    )
    parser.add_argument(
        "--nameserver",
        metavar="IP",
        help="Force a specific resolver IP (default: system resolver)",
    )
    parser.add_argument(
        "--nsec3-rounds",
        type=int,
        default=30,
        metavar="N",
        help="Number of random probes for NSEC3 hash collection",
    )
    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        help=(
            "Wordlist for NSEC3 hash cracking. "
            "Uncracked hashes are written to <domain>_nsec3.hashes. "
            "Without this flag, all hashes are written to <domain>_nsec3.hashes."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point - parses arguments and delegates to run()."""
    args = parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)-8s %(message)s",
    )

    wordlist = None
    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            log.error("Wordlist file not found: %s", args.wordlist)
            sys.exit(1)
        with open(args.wordlist, "r", encoding="latin-1") as f:
            wordlist = [line.strip() for line in f if line.strip()]
        log.info("Loaded %d words from '%s'.", len(wordlist), args.wordlist)

    run(
        domain=args.domain,
        max_steps=args.max_steps,
        nameserver=args.nameserver,
        nsec3_rounds=args.nsec3_rounds,
        wordlist=wordlist,
    )


if __name__ == "__main__":
    main()
