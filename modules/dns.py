"""DNS inspection helpers used by the TraceX terminal interface."""

from __future__ import annotations

import ipaddress
import time
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import dns.flags
import dns.resolver
import dns.reversename


DEFAULT_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "SRV",
    "CAA",
    "DS",
    "DNSKEY",
    "TLSA",
    "HTTPS",
    "SVCB",
    "NAPTR",
    "SSHFP",
    "DNAME",
)

POLICY_QUERIES = {
    "SPF": "{domain}",
    "DMARC": "_dmarc.{domain}",
    "MTA-STS": "_mta-sts.{domain}",
    "TLS-RPT": "_smtp._tls.{domain}",
}


def normalize_target(value: str) -> str:
    """Return a DNS-safe hostname from a domain, URL, or trailing-dot name."""
    target = value.strip()
    if "://" in target:
        target = urlsplit(target).hostname or ""
    else:
        target = target.split("/", 1)[0]
        if target.startswith("[") and "]" in target:
            target = target[1 : target.index("]")]
        elif target.count(":") == 1 and target.rsplit(":", 1)[1].isdigit():
            target = target.rsplit(":", 1)[0]

    target = target.rstrip(".").strip()
    if not target:
        raise ValueError("A domain or IP address is required.")

    try:
        return target.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("The domain contains invalid characters.") from error


def _record_value(record: Any, record_type: str) -> str:
    """Convert dnspython records into concise, stable display values."""
    if record_type == "TXT":
        return "".join(
            part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
            for part in record.strings
        )
    if record_type == "MX":
        return f"{record.preference} {record.exchange.to_text().rstrip('.')}"
    if record_type == "SOA":
        return (
            f"{record.mname.to_text().rstrip('.')} "
            f"{record.rname.to_text().rstrip('.')} "
            f"serial={record.serial} refresh={record.refresh} "
            f"retry={record.retry} expire={record.expire} minimum={record.minimum}"
        )
    if record_type == "SRV":
        return (
            f"priority={record.priority} weight={record.weight} "
            f"port={record.port} target={record.target.to_text().rstrip('.') }"
        )
    if record_type == "CAA":
        value = record.value.decode("utf-8", errors="replace")
        tag = record.tag.decode() if isinstance(record.tag, bytes) else str(record.tag)
        return f"{record.flags} {tag} {value}"
    return record.to_text().strip().rstrip(".")


def _query_record(
    resolver: dns.resolver.Resolver, target: str, record_type: str
) -> tuple[list[str], str | None]:
    try:
        answer = resolver.resolve(target, record_type, raise_on_no_answer=False)
        values = [_record_value(record, record_type) for record in answer]
        return list(dict.fromkeys(values)), None
    except dns.resolver.NXDOMAIN:
        return [], "name does not exist"
    except dns.resolver.NoAnswer:
        return [], "no answer"
    except dns.resolver.NoNameservers:
        return [], "no nameservers available"
    except dns.exception.Timeout:
        return [], "query timed out"
    except dns.exception.DNSException as error:
        return [], str(error) or "DNS query failed"


def _reverse_lookup(resolver: dns.resolver.Resolver, address: str) -> list[str]:
    try:
        reverse_name = dns.reversename.from_address(address)
        answer = resolver.resolve(reverse_name, "PTR")
        return list(dict.fromkeys(record.to_text().rstrip(".") for record in answer))
    except (dns.exception.DNSException, ValueError):
        return []


def dns_lookup(
    domain: str,
    record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES,
    timeout: float = 3.0,
    nameservers: tuple[str, ...] | None = None,
    include_policies: bool = True,
) -> dict[str, Any] | None:
    """Resolve a hostname or IP and return all useful results in one structure.

    Individual record failures are retained in ``errors`` so a missing optional
    record never hides successful answers from other record types.
    """
    try:
        target = normalize_target(domain)
    except ValueError:
        return None

    resolver = dns.resolver.Resolver(configure=True)
    if nameservers:
        resolver.nameservers = list(dict.fromkeys(nameservers))
    resolver.timeout = timeout
    resolver.lifetime = timeout
    started = time.perf_counter()
    records: dict[str, Any] = {}
    errors: dict[str, str] = {}
    policies: dict[str, list[str]] = {}

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None

    if address is not None:
        records["PTR"] = _reverse_lookup(resolver, target)
        if not records["PTR"]:
            errors["PTR"] = "no reverse record"
        query_name = target
    else:
        query_name = target
        for record_type in dict.fromkeys(item.upper() for item in record_types):
            values, error = _query_record(resolver, query_name, record_type)
            if values:
                records[record_type] = values
            if error and record_type not in {"A", "AAAA"}:
                errors[record_type] = error

        if include_policies:
            for policy_name, template in POLICY_QUERIES.items():
                policy_name_query = template.format(domain=query_name)
                values, error = _query_record(resolver, policy_name_query, "TXT")
                if values:
                    policies[policy_name] = values
                elif error not in {"name does not exist", "no answer"}:
                    errors[policy_name] = error or "policy query failed"

    ipv4 = records.get("A", [])
    ipv6 = records.get("AAAA", [])
    for address_text in (*ipv4, *ipv6):
        records.setdefault("reverse", {})
        records["reverse"][address_text] = _reverse_lookup(resolver, address_text)

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    ds_present = bool(records.get("DS"))
    dnskey_present = bool(records.get("DNSKEY"))
    if ds_present and dnskey_present:
        dnssec_status = "signed"
    elif ds_present or dnskey_present:
        dnssec_status = "partially configured"
    else:
        dnssec_status = "unsigned or unavailable"
    return {
        "domain": query_name,
        "is_ip": address is not None,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "records": records,
        "errors": errors,
        "resolver": list(resolver.nameservers),
        "elapsed_ms": elapsed_ms,
        "query_count": len(record_types) + (len(POLICY_QUERIES) if include_policies else 0),
        "policies": policies,
        "dnssec": {
            "status": dnssec_status,
            "ds_records": len(records.get("DS", [])),
            "dnskey_records": len(records.get("DNSKEY", [])),
        },
        "has_answers": bool(records or policies),
    }