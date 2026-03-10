#!/usr/bin/env python3
"""
ZoneRipper - DNSSEC Zone Walking Tester

Probes a domain for DNSSEC zone-walking exposure:
  - NSEC zones  : follows the NSEC chain to enumerate all owner names.
  - NSEC3 zones : actively walks the hash ring to collect all NSEC3 hashes,
                  then optionally cracks them via dictionary attack.

Install:
    pip install dnspython

Usage (CLI):
    python3 zoneripper.py <domain> [options]

Usage (module):
    from zoneripper import run
    results = run("example.com", max_steps=100, nameserver="8.8.8.8")

Examples:
    python3 zoneripper.py example.com
    python3 zoneripper.py example.com --max-steps 100 --nameserver 8.8.8.8
    python3 zoneripper.py example.com --wordlist words.txt
"""

import argparse
import base64
import bisect
import hashlib
import itertools
import logging
import os
import string
import sys
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
# Constants
# ─────────────────────────────────────────────────────────────

# SHA-1 produces 20-byte digests; these bound the flat hash space used by HashRing.
_HASH_MIN = b"\x00" * 20
_HASH_MAX = b"\xff" * 20

# DNS NSEC3 uses base32hex (RFC 4648 §7) with alphabet 0–9 A–V,
# NOT standard base32 (A–Z 2–7). Python's base64 module only speaks
# standard base32, so we translate alphabets before encoding/decoding.
_B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_B32STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_TO_STD = str.maketrans(_B32HEX, _B32STD)  # base32hex → standard
_TO_B32HEX = str.maketrans(_B32STD, _B32HEX)  # standard  → base32hex


# ─────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────


@dataclass
class Nsec3Params:
    """NSEC3 algorithm parameters extracted from a zone."""

    algorithm: int  # 1 = SHA-1 (only algorithm defined in RFC 5155)
    flags: int  # 1 = opt-out
    iterations: int  # extra hash rounds (0–2500)
    salt: bytes  # raw salt bytes (may be empty)
    salt_hex: str  # hex-encoded salt, or "-" for empty


@dataclass
class Nsec3Hash:
    """A single (owner_hash → next_hash) link from one NSEC3 record."""

    owner_b32: str  # base32hex owner hash (first label of the DNS name)
    next_b32: str  # base32hex next hash  (rdata .next field)
    types: list[str]  # RR types present at this owner name
    source_ns: str  # NS IP that returned this record


@dataclass
class Nsec3WalkResult:
    """Aggregated result of an NSEC3 enumeration pass."""

    params: Optional[Nsec3Params]
    hashes: list[Nsec3Hash] = field(default_factory=list)
    cracked: dict[str, str] = field(default_factory=dict)  # owner_b32 → plaintext label


@dataclass
class HashInterval:
    """A covered half-open interval [start, end) in the flat 20-byte hash space."""

    start: bytes
    end: bytes


class HashRing:
    """
    Tracks which portions of the NSEC3 hash space have been covered.

    Internally stores a sorted, non-overlapping list of HashInterval objects
    that together represent all hash ranges seen so far.  Because individual
    NSEC3 records can "wrap around" (owner hash > next hash, i.e. the last
    record in the zone points back to the first hash), wrap-around intervals
    are split into two linear segments on insertion so that all arithmetic
    stays simple and monotone.

    The hash space is treated as the flat range [0x00*20, 0xff*20], not as a
    true ring. Completion is detected when that entire flat range is covered.
    """

    def __init__(self) -> None:
        self._intervals: list[HashInterval] = []

    # ── public interface ──────────────────────────────────────

    def insert(self, start_b32: str, end_b32: str) -> None:
        """
        Record coverage of the interval (start_b32, end_b32).

        Wrap-around intervals (start > end in byte order) are split:
            [start → 0xff*20]  +  [0x00*20 → end]
        so that _merge only ever needs to handle linear intervals.
        """
        start = _b32hex_to_bytes(start_b32)
        end = _b32hex_to_bytes(end_b32)

        if start < end:
            to_add = [HashInterval(start, end)]
        else:
            # Wrap-around: last NSEC3 record points from a high hash back to
            # the lowest hash in the zone.  Split at the boundary.
            to_add = [
                HashInterval(start, _HASH_MAX),
                HashInterval(_HASH_MIN, end),
            ]

        for iv in to_add:
            idx = bisect.bisect_left([i.start for i in self._intervals], iv.start)
            self._intervals.insert(idx, iv)

        self._merge()

    def gaps(self) -> list[tuple[bytes, bytes]]:
        """
        Return all uncovered sub-ranges of [_HASH_MIN, _HASH_MAX] as a list
        of (gap_start, gap_end) byte pairs.  An empty list means the ring is
        fully covered.
        """
        if not self._intervals:
            return [(_HASH_MIN, _HASH_MAX)]

        result: list[tuple[bytes, bytes]] = []
        ivs = self._intervals

        # Gap before the first known interval
        if ivs[0].start > _HASH_MIN:
            result.append((_HASH_MIN, ivs[0].start))

        # Gaps between consecutive intervals
        for i in range(len(ivs) - 1):
            if ivs[i].end < ivs[i + 1].start:
                result.append((ivs[i].end, ivs[i + 1].start))

        # Gap after the last known interval
        if ivs[-1].end < _HASH_MAX:
            result.append((ivs[-1].end, _HASH_MAX))

        return result

    def is_complete(self) -> bool:
        """Return True when there are no uncovered gaps."""
        return len(self.gaps()) == 0

    # ── private helpers ───────────────────────────────────────

    def _merge(self) -> None:
        """Collapse abutting or overlapping intervals in-place."""
        merged: list[HashInterval] = []
        for iv in self._intervals:
            if merged and iv.start <= merged[-1].end:
                # Extend the last merged interval if this one reaches further
                if iv.end > merged[-1].end:
                    merged[-1] = HashInterval(merged[-1].start, iv.end)
            else:
                merged.append(HashInterval(iv.start, iv.end))
        self._intervals = merged


# ─────────────────────────────────────────────────────────────
# base32hex helpers  (used throughout for NSEC3 label encoding)
# ─────────────────────────────────────────────────────────────


def _bytes_to_b32hex(raw: bytes) -> str:
    """Encode raw bytes as uppercase base32hex (RFC 4648 §7), no padding."""
    return base64.b32encode(raw).decode().rstrip("=").upper().translate(_TO_B32HEX)


def _b32hex_to_bytes(b32hex: str) -> bytes:
    """Decode a base32hex string (as it appears in DNS NSEC3 owner labels)."""
    padded = b32hex.upper().translate(_TO_STD) + "=" * (-len(b32hex) % 8)
    return base64.b32decode(padded)


# ─────────────────────────────────────────────────────────────
# Resolver / transport helpers
# ─────────────────────────────────────────────────────────────


def make_resolver(nameserver: Optional[str] = None) -> dns.resolver.Resolver:
    """Return a Resolver with the DNSSEC OK (DO) bit set."""
    r = dns.resolver.Resolver(configure=True)
    if nameserver:
        r.nameservers = [nameserver]
    r.use_edns(ednsflags=dns.flags.DO, payload=4096)
    return r


def udp_query(
    qname: str,
    rdtype,
    nameserver_ip: str,
    timeout: float = 5.0,
) -> Optional[dns.message.Message]:
    """
    Send a single UDP query with the DO bit set.

    Returns the parsed Message on success, or None on any DNS/network error.
    Using raw UDP (instead of the high-level Resolver) lets us inspect the
    full authority section, which is where NSEC/NSEC3 records appear on
    NXDOMAIN responses.
    """
    try:
        name = dns.name.from_text(qname)
        req = dns.message.make_query(name, rdtype, use_edns=True, want_dnssec=True)
        return dns.query.udp(req, nameserver_ip, timeout=timeout)
    except dns.exception.DNSException:
        return None


def resolve_to_ip(hostname: str, resolver: dns.resolver.Resolver) -> Optional[str]:
    """Resolve a hostname to its first A record, or None on failure."""
    try:
        ans = resolver.resolve(hostname, "A", raise_on_no_answer=False)
        if ans.rrset:
            return str(list(ans.rrset)[0].address)
    except dns.exception.DNSException:
        pass
    return None


def get_zone_nameserver_ips(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    """
    Return the IP addresses of all authoritative NS records for *domain*.

    Large TLDs run anycast clusters where individual nodes may rate-limit or
    silently drop NSEC/NSEC3 queries differently.  Returning all IPs lets
    callers rotate through the full set rather than relying on a single node.
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
    """Return True when at least one DNSKEY record exists at the zone apex."""
    try:
        ans = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        return bool(ans.rrset)
    except dns.exception.DNSException:
        return False


def detect_nsec_type(
    domain: str,
    ns_ips: list[str],
    timeout: float = 5.0,
) -> tuple[str, Optional[str]]:
    """
    Probe all authoritative NS IPs and return the first one that responds
    with NSEC or NSEC3 records.

    Returns (nsec_type, ns_ip) where nsec_type is "NSEC" | "NSEC3" | "UNKNOWN"
    and ns_ip is the responding nameserver IP, or None if none responded.
    """
    probe = f"_zzzonewalk_probe_99_.{domain}"

    for ns_ip in ns_ips:
        log.debug("Probing %s for denial-of-existence type...", ns_ip)
        response = udp_query(probe, dns.rdatatype.A, ns_ip, timeout)
        if response is None:
            log.debug("  %s — no response", ns_ip)
            continue

        rdtypes = {rrset.rdtype for rrset in response.authority}

        if dns.rdatatype.NSEC3 in rdtypes:
            log.debug("  %s — NSEC3 detected", ns_ip)
            return "NSEC3", ns_ip
        if dns.rdatatype.NSEC in rdtypes:
            log.debug("  %s — NSEC detected", ns_ip)
            return "NSEC", ns_ip

        log.debug("  %s — no NSEC/NSEC3 in authority section", ns_ip)

    return "UNKNOWN", None


# ─────────────────────────────────────────────────────────────
# NSEC record helpers
# ─────────────────────────────────────────────────────────────


def parse_nsec_types(rdata) -> list[str]:
    """
    Extract RR type names from an NSEC or NSEC3 rdata bitmap.

    dnspython represents the type bitmap as a list of (window_number, bitmap)
    pairs; this function iterates all set bits and converts each to its
    human-readable type name.
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

    Rotating through all known NS IPs makes the walk resilient to per-node
    rate-limiting on anycast nameservers.

    Returns (next_owner_name, [rr_type_strings]), or (None, []) on failure.
    """
    for ns_ip in ns_ips:
        response = udp_query(owner, dns.rdatatype.NSEC, ns_ip, timeout)
        if response is None:
            log.debug("No response from %s for NSEC %s — trying next NS", ns_ip, owner)
            continue

        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    rdata = list(rrset)[0]
                    next_name = str(rdata.next).rstrip(".")
                    types = parse_nsec_types(rdata)
                    log.debug("NSEC record from %s for %s", ns_ip, owner)
                    return next_name, types

        log.debug("NS %s returned no NSEC for %s — trying next NS", ns_ip, owner)

    return None, []


# ─────────────────────────────────────────────────────────────
# NSEC zone walking engine
# ─────────────────────────────────────────────────────────────


def is_valid_hostname_label(label: str) -> bool:
    """
    Return True if *label* looks like a real DNS hostname component.

    Rejects labels containing null bytes or non-printable characters — these
    are synthetic values injected by some nameservers to stall zone walkers.
    """
    if not label:
        return False
    if "\\000" in label or "\x00" in label:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.*")
    return all(c in allowed for c in label)


def is_valid_zone_name(name: str, domain: str) -> bool:
    """
    Return True if *name* is a plausible real owner name inside *domain*.

    Strips the zone suffix and validates every remaining label individually.
    """
    if name == domain:
        return True
    suffix = f".{domain}"
    if not name.endswith(suffix):
        return False
    subdomain = name[: -len(suffix)]
    return all(is_valid_hostname_label(lbl) for lbl in subdomain.split("."))


def walk_zone(
    domain: str, ns_ips: list[str], max_steps: Optional[int] = 50
) -> list[dict]:
    """
    Follow the NSEC chain starting at the zone apex.

    Each step queries the current owner for its NSEC record and advances to
    the next owner name.  Synthetic "trap" names injected by hardened
    nameservers are detected and skipped.

    Returns a list of {"name": str, "types": [str]} dicts for every real
    owner name discovered (excluding the zone apex itself).
    """
    discovered: list[dict] = []
    seen: set[str] = set()
    current = domain
    trap_streak = 0
    MAX_TRAP_STREAK = 3

    log.debug("%-48s  %s", "Owner", "Next")
    log.debug("%s  %s", "-" * 48, "----")

    step_iter = itertools.count() if max_steps is None else range(max_steps)
    for step in step_iter:
        if current in seen:
            log.info("Loop detected at '%s' — walk complete.", current)
            break
        seen.add(current)

        next_name, types = get_nsec_record(current, ns_ips)
        if not next_name:
            log.info("%-48s  (no NSEC record — stopping)", current)
            break

        # Detect synthetic / trap names
        if not is_valid_zone_name(next_name, domain):
            trap_streak += 1
            log.warning("%-48s  synthetic next='%s' (skipping)", current, next_name)
            if trap_streak >= MAX_TRAP_STREAK:
                log.warning(
                    "Trap pattern detected (%d consecutive synthetic names) — aborting.",
                    trap_streak,
                )
                break
            current = next_name  # jump through the trap to find real names beyond it
            continue

        trap_streak = 0
        log.info("%-48s  %s", current, next_name)

        if current != domain and is_valid_zone_name(current, domain):
            discovered.append({"name": current, "types": types})

        if next_name == domain:
            log.info("Returned to zone apex — full loop completed.")
            break

        if not (next_name.endswith(f".{domain}") or next_name == domain):
            log.info("Next name '%s' is outside zone — stopping.", next_name)
            break

        current = next_name
    else:
        if max_steps is not None:
            log.warning("Reached max-steps limit (%d).", max_steps)

    return discovered


# ─────────────────────────────────────────────────────────────
# NSEC3 hash collection — parsing helpers
# ─────────────────────────────────────────────────────────────


def _extract_nsec3_params(rdata) -> Optional[Nsec3Params]:
    """Extract NSEC3 zone parameters from a single rdata object."""
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
    Build an Nsec3Hash from a single NSEC3 rdata object.

    dnspython exposes NSEC3 rdata with:
        .algorithm  .flags  .iterations  .salt  .next  .windows
    The owner label (first DNS name label) is already the base32hex hash.
    The .next field holds the raw bytes of the next hash in the chain.
    """
    try:
        return Nsec3Hash(
            owner_b32=owner_label.upper(),
            next_b32=_bytes_to_b32hex(rdata.next),
            types=parse_nsec_types(rdata),
            source_ns=ns_ip,
        )
    except Exception as exc:
        log.debug("Failed to parse NSEC3 rdata: %s", exc)
        return None


# ─────────────────────────────────────────────────────────────
# NSEC3 hash collection — active walk
# ─────────────────────────────────────────────────────────────


def _hash_falls_in_gap(h: bytes, gap_start: bytes, gap_end: bytes) -> bool:
    """
    Return True if *h* lies strictly inside the open interval (gap_start, gap_end).

    Because HashRing now stores only linear (non-wrapping) intervals and all
    gaps are expressed in the flat [MIN, MAX] space, gap_end is always greater
    than gap_start and the simple comparison is sufficient.
    """
    return gap_start < h < gap_end


def _label_generator():
    """
    Yield candidate DNS labels in ascending length order, then lexicographically.

    Produces: 0–9, a–z, 00–0z, 01–0z, ..., aa–zz, 000–zzz, ...
    """
    charset = string.digits + string.ascii_lowercase
    length = 1
    while True:
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)
        length += 1


def find_candidate_for_any_gap(
    domain: str,
    salt: bytes,
    iterations: int,
    gaps: list[tuple[bytes, bytes]],
    label_iter,
) -> tuple[str, bytes, tuple[bytes, bytes]] | None:
    """
    Consume labels from the shared iterator until one hashes into any gap.

    Checking every label against all gaps at once ensures no label is ever
    wasted — if a hash misses one gap but falls into another, it is still
    used immediately.

    Iterates indefinitely until a match is found. Termination is guaranteed
    because _label_generator covers the full label space and the hash space
    is finite — every gap will eventually be hit.
    """
    while True:
        label = next(label_iter)
        try:
            raw = _nsec3_hash(label, domain, salt, iterations)
        except (ValueError, UnicodeEncodeError):
            continue
        for gap in gaps:
            if _hash_falls_in_gap(raw, gap[0], gap[1]):
                return label, raw, gap


def collect_nsec3_hashes(
    domain: str,
    ns_ips: list[str],
    rounds: Optional[int] = 100,
    timeout: float = 5.0,
) -> Nsec3WalkResult:
    """
    Actively enumerate all NSEC3 hashes in *domain* using a gap-targeted walk.

    Algorithm
    ---------
    Phase 1 — Bootstrap:
        Query a fixed name ("0.<domain>") to obtain the zone's NSEC3 parameters
        and seed the hash ring with the first known intervals.  Using a fixed
        name (rather than random UUIDs) makes the starting state deterministic.

    Phase 2 — Active gap targeting:
        Repeat until the hash ring is fully covered or *rounds* is exhausted:
        1. Compute the current uncovered gaps in the hash ring.
        2. Generate candidate labels (via _label_generator) until one hashes
           into any gap — checking all gaps per label to waste nothing.
        3. Query that candidate; parse every NSEC3 record from the response
           (both answer and authority sections) into the ring.

    Each DNS query typically returns 2–3 NSEC3 records (closest encloser,
    next closer, wildcard proofs), so the ring fills faster than one record
    per query.
    """
    result = Nsec3WalkResult(params=None)
    ring = HashRing()

    # ── inner helper: parse a response and update shared state ────────────

    def _process_response(response: dns.message.Message, ns_ip: str) -> int:
        """
        Extract all NSEC3 records from *response* (answer + authority sections),
        add any new ones to *result* and *ring*, and return the count added.
        """
        added = 0
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype != dns.rdatatype.NSEC3:
                    continue
                for rdata in rrset:
                    # Capture zone parameters from the first NSEC3 record seen
                    if result.params is None:
                        result.params = _extract_nsec3_params(rdata)
                        if result.params:
                            log.info(
                                "NSEC3 params — algorithm: %d  iterations: %d  salt: %s",
                                result.params.algorithm,
                                result.params.iterations,
                                result.params.salt_hex,
                            )

                    owner_label = str(rrset.name).split(".")[0].upper()
                    h = _parse_nsec3_rdata(rdata, owner_label, ns_ip)
                    if h and owner_label not in {x.owner_b32 for x in result.hashes}:
                        result.hashes.append(h)
                        ring.insert(h.owner_b32, h.next_b32)
                        added += 1
        return added

    # ── Phase 1: deterministic bootstrap ──────────────────────────────────

    log.info("Phase 1: bootstrapping with apex probe (0.%s)...", domain)
    for ns_ip in ns_ips:
        resp = udp_query(f"0.{domain}", dns.rdatatype.A, ns_ip, timeout)
        if resp:
            _process_response(resp, ns_ip)
            break

    if result.params is None:
        log.warning("No NSEC3 records in bootstrap response — zone may not use NSEC3.")
        return result

    # ── Phase 2: active gap-targeted walk ─────────────────────────────────

    log.info(
        "Phase 2: active gap-targeted walk (%s)...",
        f"max {rounds} rounds" if rounds is not None else "unlimited rounds",
    )
    label_iter = _label_generator()

    round_iter = itertools.count() if rounds is None else range(rounds)
    for step in round_iter:
        gaps = ring.gaps()
        if not gaps:
            log.info(
                "Hash ring fully covered after %d step(s). Total hashes: %d",
                step,
                len(result.hashes),
            )
            break

        log.debug(
            "Step %d: %d gap(s), %d hash(es) so far",
            step,
            len(gaps),
            len(result.hashes),
        )

        label, _, matched_gap = find_candidate_for_any_gap(
            domain,
            result.params.salt,
            result.params.iterations,
            gaps,
            label_iter,
        )
        log.debug(
            "  label=%-12s  matched gap %s…%s",
            label,
            matched_gap[0].hex()[:8],
            matched_gap[1].hex()[:8],
        )

        probe = f"{label}.{domain}"
        for ns_ip in ns_ips:
            resp = udp_query(probe, dns.rdatatype.A, ns_ip, timeout)
            if resp:
                new = _process_response(resp, ns_ip)
                if new:
                    log.debug("    +%d interval(s) → total %d", new, len(result.hashes))
                break
    else:
        if rounds is not None:
            log.warning(
                "Round limit (%d) reached with %d gap(s) remaining.",
                rounds,
                len(ring.gaps()),
            )

    log.info("Collected %d unique NSEC3 hash(es).", len(result.hashes))
    return result


# ─────────────────────────────────────────────────────────────
# NSEC3 hash cracking  (pure-Python SHA-1, RFC 5155 §5)
# ─────────────────────────────────────────────────────────────


def _is_valid_dns_label(label: str) -> bool:
    """
    Return True if *label* is a valid single DNS label (≤63 UTF-8 bytes).

    Large wordlists (e.g. rockyou) contain entries that exceed this limit or
    contain non-encodable characters; silently skipping them keeps cracking
    safe to run against arbitrary input files.
    """
    try:
        encoded = label.lower().encode()
        return 1 <= len(encoded) <= 63
    except (UnicodeEncodeError, UnicodeDecodeError):
        return False


def _nsec3_hash(label: str, domain: str, salt: bytes, iterations: int) -> bytes:
    """
    Compute the NSEC3 hash for *label*.*domain* as specified in RFC 5155 §5:

        IH(salt, x, 0) = H(x || salt)
        IH(salt, x, k) = H(IH(salt, x, k-1) || salt)   for k > 0

    where H = SHA-1 and x is the wire-format FQDN with all labels lowercased.
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
    Attempt to reverse collected NSEC3 hashes via dictionary attack.

    For each candidate in *wordlist*, computes NSEC3(candidate + "." + domain)
    using the zone's own parameters and checks it against all collected hashes.
    A match reveals the plaintext subdomain label for that hash.

    Returns a dict mapping owner_b32 → cracked plaintext label.
    Invalid candidates (too long, non-encodable) are silently skipped.
    """
    if result.params is None:
        log.warning("No NSEC3 params available — cannot crack.")
        return {}
    if result.params.algorithm != 1:
        log.warning(
            "NSEC3 algorithm %d is not SHA-1 — pure-Python cracking not supported.",
            result.params.algorithm,
        )
        return {}

    salt = result.params.salt
    iterations = result.params.iterations
    targets = {h.owner_b32: h for h in result.hashes}

    if not targets:
        return {}

    log.info(
        "Cracking %d hash(es) (salt=%s, iter=%d) against %d candidate(s)...",
        len(targets),
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
        b32 = _bytes_to_b32hex(raw)
        if b32 in targets and b32 not in cracked:
            cracked[b32] = candidate
            log.info("  CRACKED: %s  →  %s.%s", b32, candidate, domain)

    if skipped:
        log.debug("Skipped %d invalid/oversized candidate(s).", skipped)
    log.info("Cracked %d / %d hash(es).", len(cracked), len(targets))
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

    Example (domain "sh", salt "73", 0 iterations):
        9clkef9t1cpn5jp5ltaohtp49dqi9foj:.sh:73:0

    When *uncracked_only* is True, already-cracked hashes are omitted so the
    file can be used to continue cracking with a larger offline wordlist.

    Crack offline with:
        hashcat -m 8300 --keep-guessing <file> <wordlist>
    """
    if not result.hashes or result.params is None:
        log.warning("Nothing to export.")
        return

    salt_hex = result.params.salt_hex if result.params.salt_hex != "-" else ""
    zone = f".{domain}"
    count = 0

    with open(path, "w") as fh:
        for h in result.hashes:
            if uncracked_only and h.owner_b32 in result.cracked:
                continue
            fh.write(
                f"{h.owner_b32.lower()}:{zone}:{salt_hex}:{result.params.iterations}\n"
            )
            count += 1

    qualifier = "uncracked " if uncracked_only else ""
    log.info("Exported %d %shash(es) to '%s' (hashcat -m 8300)", count, qualifier, path)
    log.info("Crack offline with: hashcat -m 8300 --keep-guessing %s <wordlist>", path)


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────


def run(
    domain: str,
    max_steps: Optional[int] = 50,
    nameserver: Optional[str] = None,
    nsec3_rounds: Optional[int] = 100,
    wordlist: Optional[list[str]] = None,
) -> dict:
    """
    Run a full DNSSEC zone-walking assessment against *domain*.

    NSEC zones  → follows the NSEC chain; returns all discovered owner names.
    NSEC3 zones → walks the hash ring to collect all hashes, then:
                  - with wordlist:    attempts cracking; exports uncracked hashes.
                  - without wordlist: exports all hashes for offline cracking.

    Parameters
    ----------
    domain       : Zone apex to test (e.g. "example.com").
    max_steps    : Maximum NSEC hops before giving up.
    nameserver   : Force a specific resolver IP; uses system resolver when None.
    nsec3_rounds : Maximum active-walk rounds for NSEC3 hash collection.
    wordlist     : Candidate labels for NSEC3 cracking (None = skip cracking).

    Returns
    -------
    dict with keys:
        "nsec_type"  : "NSEC" | "NSEC3" | "UNKNOWN" | "NONE"
        "nsec_names" : list[dict]          — discovered names (NSEC path only)
        "nsec3"      : Nsec3WalkResult | None
    """
    domain = domain.strip().rstrip(".")
    resolver = make_resolver(nameserver)
    SEP = "=" * 60

    log.info(SEP)
    log.info("ZoneRipper — DNSSEC Zone Walking Tester")
    log.info("Target     : %s", domain)
    if nameserver:
        log.info("Nameserver : %s", nameserver)
    log.info(SEP)

    # 1. Confirm DNSSEC is enabled --------------------------------
    log.info("[1] Checking for DNSKEY records...")
    if not check_dnssec_enabled(domain, resolver):
        log.warning("No DNSKEY found — DNSSEC is NOT enabled on '%s'.", domain)
        log.warning("Zone walking requires DNSSEC; nothing to test.")
        return {"nsec_type": "NONE", "nsec_names": [], "nsec3": None}
    log.info("DNSKEY present — DNSSEC is ENABLED.")

    # 2. Resolve authoritative nameservers ------------------------
    log.info("[2] Resolving authoritative nameservers...")
    ns_ips = get_zone_nameserver_ips(domain, resolver)
    if not ns_ips:
        fallback = nameserver or resolver.nameservers[0]
        log.warning("Could not resolve any NS; falling back to %s", fallback)
        ns_ips = [fallback]
    else:
        log.info("Authoritative NS IPs: %s", ", ".join(ns_ips))

    # 3. Detect NSEC vs NSEC3 -------------------------------------
    log.info("[3] Detecting denial-of-existence mechanism...")
    nsec_type, nsec_ns_ip = detect_nsec_type(domain, ns_ips)
    log.info("Detected: %s (via %s)", nsec_type, nsec_ns_ip or "none")

    # Put the responding NS first so all subsequent queries prefer it
    if nsec_ns_ip and nsec_ns_ip in ns_ips and ns_ips[0] != nsec_ns_ip:
        ns_ips.remove(nsec_ns_ip)
        ns_ips.insert(0, nsec_ns_ip)

    # 4a. NSEC — plain zone walk ----------------------------------
    if nsec_type == "NSEC":
        log.warning(
            "Plain NSEC detected — zone is potentially VULNERABLE to enumeration."
        )
        log.info(
            "[4] Attempting NSEC zone walk (%s)...",
            f"max {max_steps} steps" if max_steps is not None else "unlimited steps",
        )
        discovered = walk_zone(domain, ns_ips, max_steps=max_steps)

        log.info("[5] Results")
        log.info(SEP)
        if discovered:
            log.info("Enumerated %d name(s):", len(discovered))
            log.info("%-48s  RR Types", "Hostname")
            log.info("%s  %s", "-" * 48, "--------")
            for entry in discovered:
                log.info("%-48s  %s", entry["name"], ", ".join(entry["types"]) or "-")
            log.warning("Verdict: VULNERABLE — zone walking succeeded on '%s'.", domain)
            log.warning("Remediation: migrate to NSEC3 with opt-out (RFC 5155).")
        else:
            log.info("No names enumerated via zone walking.")
            log.info("Verdict: no zone walking exposure detected on '%s'.", domain)
        log.info(SEP)
        return {"nsec_type": "NSEC", "nsec_names": discovered, "nsec3": None}

    # 4b. NSEC3 — hash collection + optional cracking -------------
    if nsec_type == "NSEC3":
        log.info(
            "[4] Collecting NSEC3 hashes (%s)...",
            f"max {nsec3_rounds} rounds"
            if nsec3_rounds is not None
            else "unlimited rounds",
        )
        nsec3_result = collect_nsec3_hashes(domain, ns_ips, rounds=nsec3_rounds)
        export_path = f"{domain}_nsec3.hashes"

        if wordlist:
            log.info("[5] Attempting dictionary crack of NSEC3 hashes...")
            crack_nsec3_hashes(nsec3_result, domain, wordlist=wordlist)

            log.info("[6] Results")
            log.info(SEP)
            log.info("Collected %d unique NSEC3 hash(es).", len(nsec3_result.hashes))
            if nsec3_result.cracked:
                log.warning(
                    "Cracked %d / %d hash(es):",
                    len(nsec3_result.cracked),
                    len(nsec3_result.hashes),
                )
                for b32, label in nsec3_result.cracked.items():
                    log.warning("  %s  →  %s.%s", b32, label, domain)
                log.warning(
                    "Verdict: NSEC3 hashes partially reversed — subdomain names exposed."
                )

            uncracked = len(nsec3_result.hashes) - len(nsec3_result.cracked)
            if uncracked:
                export_hashcat_file(
                    nsec3_result, domain, export_path, uncracked_only=True
                )
            else:
                log.info("All hashes cracked — no output file written.")
        else:
            log.info("[5] No wordlist — writing all hashes for offline cracking.")
            log.info("[6] Results")
            log.info(SEP)
            log.info("Collected %d unique NSEC3 hash(es).", len(nsec3_result.hashes))
            export_hashcat_file(nsec3_result, domain, export_path, uncracked_only=False)

        log.info(SEP)
        return {"nsec_type": "NSEC3", "nsec_names": [], "nsec3": nsec3_result}

    # Unknown / no denial-of-existence records --------------------
    log.warning("Could not detect NSEC type for '%s'.", domain)
    return {"nsec_type": "UNKNOWN", "nsec_names": [], "nsec3": None}


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="zoneripper",
        description=(
            "ZoneRipper — DNSSEC Zone Walking Tester\n"
            "\n"
            "Probes a domain for DNSSEC zone-walking exposure:\n"
            "  NSEC zones  : enumerates all owner names by following the NSEC chain.\n"
            "  NSEC3 zones : collects all hashes via active gap-targeted walk,\n"
            "                then optionally cracks them via dictionary attack.\n"
            "\n"
            "Examples:\n"
            "  zoneripper example.com\n"
            "  zoneripper example.com -n 8.8.8.8 -w wordlist.txt\n"
            "  zoneripper example.com -r 0              # unlimited rounds\n"
            "  zoneripper example.com -l DEBUG\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "domain",
        metavar="DOMAIN",
        help="Target zone apex (e.g. example.com)",
    )
    parser.add_argument(
        "-n",
        "--nameserver",
        metavar="IP",
        help="Authoritative nameserver IP to query (default: system resolver)",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        metavar="FILE",
        help=(
            "Wordlist for NSEC3 hash cracking. "
            "Uncracked hashes are written to <domain>_nsec3.hashes. "
            "Without this flag all hashes are written to that file."
        ),
    )
    parser.add_argument(
        "-s",
        "--max-steps",
        type=int,
        default=50,
        metavar="N",
        help="Max NSEC hops to follow; 0 = unlimited (default: %(default)s)",
    )
    parser.add_argument(
        "-r",
        "--nsec3-rounds",
        type=int,
        default=100,
        metavar="N",
        help="Max NSEC3 walk rounds; 0 = unlimited (default: %(default)s)",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        metavar="LEVEL",
        help="Logging verbosity: DEBUG INFO WARNING ERROR (default: %(default)s)",
    )

    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
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
        with open(args.wordlist, encoding="latin-1") as fh:
            wordlist = [line.strip() for line in fh if line.strip()]
        log.info("Loaded %d word(s) from '%s'.", len(wordlist), args.wordlist)

    run(
        domain=args.domain,
        max_steps=args.max_steps or None,
        nameserver=args.nameserver,
        nsec3_rounds=args.nsec3_rounds or None,
        wordlist=wordlist,
    )


if __name__ == "__main__":
    main()
