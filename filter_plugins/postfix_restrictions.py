"""Validate the expanded SMTP access restrictions consumed by Postfix smtpd."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping

# Built-ins and legacy spellings from Postfix smtpd_check.c::generic_checks.
SIMPLE = {
    "check_recipient_maps",
    "defer",
    "defer_if_permit",
    "defer_if_reject",
    "defer_unauth_destination",
    "permit",
    "permit_auth_destination",
    "permit_inet_interfaces",
    "permit_mx_backup",
    "permit_mynetworks",
    "permit_sasl_authenticated",
    "permit_tls_all_clientcerts",
    "permit_tls_clientcerts",
    "reject",
    "reject_authenticated_sender_login_mismatch",
    "reject_invalid_helo_hostname",
    "reject_invalid_hostname",
    "reject_known_sender_login_mismatch",
    "reject_multi_recipient_bounce",
    "reject_non_fqdn_helo_hostname",
    "reject_non_fqdn_hostname",
    "reject_non_fqdn_recipient",
    "reject_non_fqdn_sender",
    "reject_plaintext_session",
    "reject_unauth_destination",
    "reject_unauth_pipelining",
    "reject_unauthenticated_sender_login_mismatch",
    "reject_unknown_address",
    "reject_unknown_client",
    "reject_unknown_client_hostname",
    "reject_unknown_helo_hostname",
    "reject_unknown_hostname",
    "reject_unknown_recipient_domain",
    "reject_unknown_reverse_client_hostname",
    "reject_unknown_sender_domain",
    "reject_unlisted_recipient",
    "reject_unlisted_sender",
    "reject_unverified_recipient",
    "reject_unverified_sender",
    "warn_if_reject",
}

REMOVED_IN_39 = {"check_relay_domains", "permit_naked_ip_address", "reject_maps_rbl"}

LOOKUPS = {
    "check_ccert_access",
    "check_client_a_access",
    "check_client_access",
    "check_client_mx_access",
    "check_client_ns_access",
    "check_etrn_access",
    "check_helo_a_access",
    "check_helo_access",
    "check_helo_mx_access",
    "check_helo_ns_access",
    "check_policy_service",
    "check_recipient_a_access",
    "check_recipient_access",
    "check_recipient_mx_access",
    "check_recipient_ns_access",
    "check_reverse_client_hostname_a_access",
    "check_reverse_client_hostname_access",
    "check_reverse_client_hostname_mx_access",
    "check_reverse_client_hostname_ns_access",
    "check_sasl_access",
    "check_sender_a_access",
    "check_sender_access",
    "check_sender_mx_access",
    "check_sender_ns_access",
}

DNS_LISTS = {
    "permit_dnswl_client",
    "permit_rhswl_client",
    "reject_rbl",
    "reject_rbl_client",
    "reject_rhsbl_client",
    "reject_rhsbl_helo",
    "reject_rhsbl_recipient",
    "reject_rhsbl_reverse_client",
    "reject_rhsbl_sender",
}


def tokens(value: str) -> Iterator[str]:
    """Split Postfix comma/whitespace lists, preserving nested brace groups as arguments."""
    start = depth = 0
    for index, character in enumerate(value):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                raise ValueError("unexpected closing brace")
        elif depth == 0 and (character == "," or character.isspace()):
            if index > start:
                yield value[start:index]
            start = index + 1
    if depth:
        raise ValueError("unclosed brace")
    if start < len(value):
        yield value[start:]


def lookup_argument(word: str) -> bool:
    """Recognize ordinary, proxied, inline and braced table or policy endpoints."""
    return re.match(r"^(?:\{\s*)?[a-zA-Z][a-zA-Z0-9_-]*:.+", word) is not None


def class_references(value: str, classes: set[str], pre_39: bool) -> set[str]:
    """Check command names and consume the arguments that belong to those commands."""
    references = set()
    words = tokens(value)
    for word in words:
        keyword = word.lower()
        if keyword in REMOVED_IN_39:
            if not pre_39:
                raise ValueError(
                    f"SMTP restriction {word!r} was removed in Postfix 3.9"
                )
            continue
        # Postfix implements this built-in as a case-sensitive named class.
        if (
            keyword in SIMPLE
            or word == "reject_sender_login_mismatch"
            or lookup_argument(word)
        ):
            continue
        if keyword in LOOKUPS or keyword in DNS_LISTS or keyword == "sleep":
            argument = next(words, "")
            if not argument or (keyword in LOOKUPS and not lookup_argument(argument)):
                raise ValueError(f"missing or invalid argument for {keyword}")
            if keyword == "sleep" and not argument.isdecimal():
                raise ValueError("sleep requires a number of seconds")
        elif word in classes:
            references.add(word)
        else:
            raise ValueError(f"unknown SMTP restriction {word!r}")
    return references


def validate_classes(references: Mapping[str, set[str]]) -> None:
    """Reject recursive named classes before a client can select one through an access map."""
    pending = dict(references)
    while pending:
        resolved = {
            name
            for name, depends_on in pending.items()
            if not depends_on.intersection(pending)
        }
        if not resolved:
            raise ValueError(
                "recursive restriction classes: " + ", ".join(sorted(pending))
            )
        for name in resolved:
            del pending[name]


class FilterModule:
    """Expose the SMTP restriction check to the role."""

    @staticmethod
    def valid_restrictions(
        policies: Mapping[str, Mapping[str, str]], pre_39: bool = False
    ) -> bool:
        """Validate names in their native, service-local class namespace."""
        for service, settings in policies.items():
            classes = set(tokens(settings["smtpd_restriction_classes"]))
            references = {}
            for name in classes:
                if not settings.get(name, "").strip():
                    raise ValueError(
                        f"{service}: undefined or empty restriction class {name!r}"
                    )
            for name, value in settings.items():
                if name == "smtpd_restriction_classes":
                    continue
                try:
                    refs = class_references(value, classes, pre_39)
                except ValueError as exc:
                    raise ValueError(f"{service} {name}: {exc}") from exc
                if name in classes:
                    references[name] = refs
            validate_classes(references)
        return True

    @classmethod
    def filters(cls) -> dict[str, object]:
        """Return registered filter names."""
        return {"postfix_valid_restrictions": cls.valid_restrictions}
