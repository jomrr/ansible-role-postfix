"""Translate independent SMTP listener policies into Postfix service overrides."""

from __future__ import annotations

import re
from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any

LISTS = {
    "clients",
    "milters",
    "policy_services",
    "helo_restrictions",
    "sender_restrictions",
    "recipient_restrictions",
    "dnsbl_sites",
}
LIMITS = {
    "client_auth_rate_limit",
    "client_connection_rate_limit",
    "client_connection_count_limit",
}
FIELDS = (
    LISTS
    | LIMITS
    | {
        "port",
        "address",
        "tls",
        "auth",
        "relay",
        "sender_login_match",
        "options",
        "mx",
        "postscreen",
        "greet_wait",
    }
)


def line(value: Any) -> bool:
    """Allow native single-line options without introducing a master.cf directive."""
    return isinstance(value, str) and not any(c in value for c in "\n\r\0")


def clean_options(options: dict[str, Any]) -> dict[str, str]:
    """Validate explicit native parameters before writing either Postfix file."""
    if not isinstance(options, Mapping):
        raise TypeError("Native options must be a mapping")
    result = {}
    for key, value in options.items():
        if (
            not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", key)
            or not isinstance(value, (str, int))
            or isinstance(value, bool)
        ):
            raise ValueError("Invalid Postfix option name or value")
        if not line(str(value)):
            raise ValueError(f"{key} must fit on one configuration line")
        result[key] = str(value)
    return result


def main_parameters(configuration: str, overrides: dict[str, Any]) -> str:
    """Replace complete native assignments, including their continuation lines."""
    parameters = clean_options(overrides)
    result = []
    replaced = False
    for row in configuration.splitlines():
        if row.strip() and not row[0].isspace():
            replaced = row.partition("=")[0].strip() in parameters
        if not replaced:
            result.append(row)
    result.extend(f"{key} = {value}" for key, value in parameters.items())
    return "\n".join(result) + "\n"


def unique_services(configuration: str) -> str:
    """A master.cf service is identified by its name and transport type."""
    seen = set()
    for row in configuration.splitlines():
        if not row or row[0].isspace() or row.startswith("#"):
            continue
        service = tuple(row.split()[:2])
        if service in seen:
            raise ValueError(f"Duplicate master.cf service {'/'.join(service)}")
        seen.add(service)
    return configuration


def validate_listener(name: str, spec: dict[str, Any]) -> None:
    """Reject ambiguous ports, unsafe relay combinations and invalid policy inputs."""
    if (
        not re.fullmatch(r"[a-z][a-z0-9_]*", name)
        or not isinstance(spec, Mapping)
        or set(spec) - FIELDS
    ):
        raise ValueError(f"Invalid SMTP listener definition {name}")
    if (
        not isinstance(spec.get("port"), int)
        or isinstance(spec["port"], bool)
        or not 0 < spec["port"] < 65536
    ):
        raise ValueError(f"Listener {name} requires a numeric TCP port")
    for key in LISTS & spec.keys():
        values = spec[key]
        if not isinstance(values, list) or not all(
            line(s) and s.strip() for s in values
        ):
            raise ValueError(f"Invalid {key} on {name}")
    for key in LIMITS & spec.keys():
        if (
            not isinstance(spec[key], int)
            or isinstance(spec[key], bool)
            or spec[key] < 0
        ):
            raise ValueError(f"Invalid {key} on {name}")
    for key in {"sender_login_match", "mx", "postscreen"} & spec.keys():
        if not isinstance(spec[key], bool):
            raise TypeError(f"Invalid boolean {key} on {name}")
    validate_policy(name, spec)


def validate_policy(name: str, spec: dict[str, Any]) -> None:
    """Check combinations of TLS, authentication and relay rights."""
    tls, auth, relay = (
        spec.get("tls", "encrypt"),
        spec.get("auth", "required"),
        spec.get("relay", "authenticated"),
    )
    if (
        tls not in {"none", "may", "encrypt", "wrapper"}
        or auth not in {"none", "required"}
        or relay not in {"none", "authenticated", "clients"}
    ):
        raise ValueError(f"Invalid tls, auth or relay on {name}")
    if auth == "required" and tls not in {"encrypt", "wrapper"}:
        raise ValueError(f"{name} requires TLS for SMTP AUTH")
    if relay == "authenticated" and auth != "required":
        raise ValueError(f"{name} requires authentication to relay")
    networks = [
        ip_network(
            s.strip("[]") if "/" not in s else s.replace("[", "").replace("]", ""),
            strict=False,
        )
        for s in spec.get("clients", [])
    ]
    if relay == "clients" and (not networks or any(n.prefixlen == 0 for n in networks)):
        raise ValueError(f"{name} requires explicit trusted networks for relay")
    if spec.get("postscreen") and (
        auth != "none" or relay != "none" or tls not in {"none", "may"}
    ):
        raise ValueError(
            "Postscreen requires a receiving MX listener without authenticated or network relay"
        )
    if "greet_wait" in spec and not re.fullmatch(r"[0-9]+s", str(spec["greet_wait"])):
        raise ValueError("Invalid postscreen greet_wait")
    if any(
        not re.fullmatch(r"[A-Za-z0-9_.=*:-]+", s) for s in spec.get("dnsbl_sites", [])
    ):
        raise ValueError("Invalid postscreen DNSBL site")


def screen_options(spec: dict[str, Any], extra: dict[str, str]) -> dict[str, str]:
    """Move native postscreen overrides out of the SMTP daemon options."""
    overrides = {
        key: extra.pop(key) for key in list(extra) if key.startswith("postscreen_")
    }
    if overrides and not spec.get("postscreen"):
        raise ValueError("Postscreen options require an enabled postscreen listener")
    for key, value in overrides.items():
        if key == "postscreen_cache_map":
            raise ValueError(f"Invalid postscreen option {key}")
        if key.endswith("_action") and value not in {"ignore", "enforce", "drop"}:
            raise ValueError(f"Invalid postscreen action for {key}")
    return {
        "postscreen_greet_action": "enforce",
        "postscreen_dnsbl_action": "enforce",
        "postscreen_greet_wait": spec.get("greet_wait", "6s"),
        "postscreen_dnsbl_sites": ", ".join(spec.get("dnsbl_sites", [])),
    } | overrides


def bind_service(
    name: str,
    address: str,
    port: int,
    bindings: dict[int, list[IPv4Address | IPv6Address | None]],
) -> str:
    """Format a bind endpoint and reject overlapping wildcard or specific sockets."""
    if not line(address) or (
        "%" in address
        and not re.fullmatch(r"[A-Za-z0-9_.-]+", address.partition("%")[2])
    ):
        raise ValueError(f"Invalid bind address on {name}")
    ip = ip_address(address) if address else None
    endpoints = bindings.setdefault(port, [])
    for previous in endpoints:
        if ip is not None and previous is not None and previous.version != ip.version:
            continue
        if (
            ip is None
            or previous is None
            or ip == previous
            or ip.is_unspecified
            or previous.is_unspecified
        ):
            raise ValueError(f"Overlapping bind address and port on {name}")
    endpoints.append(ip)
    if ip is None:
        return str(port)
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


def network_text(network: str) -> str:
    """Write the bracketed IPv6 network syntax expected by Postfix."""
    parsed = ip_network(network.replace("[", "").replace("]", ""), strict=False)
    if parsed.version == 6:
        return f"[{parsed.network_address}]/{parsed.prefixlen}"
    return str(parsed)


def restrictions(spec: dict[str, Any], outbound: str) -> dict[str, list[str]]:
    """Build separate restrictions for login, destination, sender and policy checks."""
    auth, relay = spec.get("auth", "required"), spec.get("relay", "authenticated")
    destination = (
        ["reject_unauth_destination"] if outbound == "none" or relay == "none" else []
    )
    if auth == "required":
        destination += ["$managed_sasl_gate"]
    elif relay == "clients":
        destination += ["permit_mynetworks", "reject_unauth_destination"]
    senders = []
    if spec.get("mx"):
        senders.append("reject_non_fqdn_sender")
    if spec.get("sender_login_match", auth == "required" or relay != "clients"):
        senders.append(
            "reject_sender_login_mismatch"
            if auth == "required"
            else "$managed_sender_protection"
        )
    if spec.get("mx"):
        senders.append("reject_unknown_sender_domain")
    recipients = (
        ["reject_non_fqdn_recipient", "reject_unknown_recipient_domain"]
        if spec.get("mx")
        else []
    ) + ["reject_unlisted_recipient"]
    return {
        "client": ["permit_mynetworks", "reject"] if spec.get("clients") else [],
        "helo": (
            ["reject_invalid_helo_hostname", "reject_non_fqdn_helo_hostname"]
            if spec.get("mx")
            else []
        )
        + spec.get("helo_restrictions", []),
        "sender": senders + spec.get("sender_restrictions", []),
        "relay": destination,
        "recipient": recipients
        + spec.get("recipient_restrictions", [])
        + ["check_policy_service " + p for p in spec.get("policy_services", [])],
    }


class FilterModule:
    """Expose listener and raw option validation."""

    @staticmethod
    def listener_services(
        data: dict[str, Any], outbound: str, discard_ehlo: str = ""
    ) -> list[dict[str, Any]]:
        """Build service policies using stable names independent of other listeners."""
        services = []
        bindings: dict[int, list[IPv4Address | IPv6Address | None]] = {}
        for name, spec in data.items():
            validate_listener(name, spec)
            endpoint = bind_service(
                name, spec.get("address", ""), spec["port"], bindings
            )
            auth = spec.get("auth", "required")
            tls = spec.get("tls", "encrypt")
            options = {
                "syslog_name": "postfix/" + name,
                "smtpd_tls_security_level": "encrypt" if tls == "wrapper" else tls,
                "smtpd_tls_wrappermode": "yes" if tls == "wrapper" else "no",
                "smtpd_sasl_auth_enable": "yes" if auth == "required" else "no",
                "smtpd_milters": ", ".join(spec.get("milters", [])),
                "milter_macro_daemon_name": "ORIGINATING"
                if auth == "required"
                else "INBOUND",
            }
            if spec.get("mx"):
                options["smtpd_etrn_restrictions"] = "reject"
                options["smtpd_discard_ehlo_keywords"] = ", ".join(
                    filter(None, ("silent-discard, etrn, dsn", discard_ehlo))
                )
            if spec.get("clients"):
                options["mynetworks"] = ", ".join(
                    network_text(n) for n in spec["clients"]
                )
            for key in sorted(LIMITS & spec.keys()):
                options["smtpd_" + key] = str(spec[key])
            policy = restrictions(spec, outbound)
            for key in policy:
                options["smtpd_" + key + "_restrictions"] = f"$managed_{name}_{key}"
            extra = clean_options(spec.get("options", {}))
            if extra.keys() & {
                "smtpd_relay_restrictions",
                "smtpd_sasl_auth_enable",
                "smtpd_tls_security_level",
                "smtpd_tls_wrappermode",
                "mynetworks",
            }:
                raise ValueError(
                    f"Use the typed listener fields for authentication and relay on {name}"
                )
            frontend = screen_options(spec, extra)
            services.append(
                {
                    "name": name,
                    "bind": endpoint,
                    "tls": tls,
                    "auth": auth,
                    "protect": "$managed_sender_protection" in policy["sender"],
                    "policy": policy,
                    "options": options | extra,
                    "postscreen": spec.get("postscreen", False),
                    "screen_options": frontend,
                }
            )
        return services

    @classmethod
    def filters(cls) -> dict[str, Any]:
        """Return registered filter names."""
        return {
            "postfix_listener_services": cls.listener_services,
            "postfix_clean_options": clean_options,
            "postfix_main_parameters": main_parameters,
            "postfix_unique_services": unique_services,
        }
