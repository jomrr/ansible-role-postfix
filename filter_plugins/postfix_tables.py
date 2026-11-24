"""Build native Postfix map definitions and identify indexes that need rebuilding."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

DIRECTORY = "/etc/postfix/managed"
SUFFIXES = {"hash": ".db", "btree": ".db", "lmdb": ".lmdb", "cdb": ".cdb"}
TEXT_TYPES = {"cidr", "regexp", "pcre", "texthash"}


def single_line(value: str) -> bool:
    """Return whether a value fits on one native configuration line."""
    return isinstance(value, str) and not any(ch in value for ch in "\r\n\0")


def provider_tables(
    providers: list[dict[str, Any]],
    senders: dict[str, str],
    port: int,
    default: str,
    relay: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Generate sender and unambiguous next-hop credentials from one provider list."""
    by_name = {p["name"]: p for p in providers}
    hops = {n: f"[{p['host']}]:{p.get('port', port)}" for n, p in by_name.items()}
    counts = Counter(hop.lower() for hop in hops.values())
    credentials = {
        s: f"{by_name[n]['username']}:{by_name[n]['password']}"
        for s, n in senders.items()
    }
    for name, hop in hops.items():
        if counts[hop.lower()] == 1 or name == default:
            credentials[hop] = (
                f"{by_name[name]['username']}:{by_name[name]['password']}"
            )
    if relay.get("username"):
        hop = f"[{relay['host']}]:{relay.get('port', 25)}"
        if hop.lower() in counts:
            raise ValueError(
                "The authenticated relayhost and providers must use distinct next hops"
            )
        credentials[hop] = f"{relay['username']}:{relay['password']}"
    return {
        "sasl_passwd": credentials,
        "sender_relay": {s: hops[n] for s, n in senders.items()},
        "sender_transport": {s: f"provider_{n}" for s, n in senders.items()},
    }


def table_entries(entries: Mapping[str, Any], ordered: bool) -> dict[str, str]:
    """Keep pattern order and turn multi-value address results into native lists."""
    result = {}
    for key, value in entries.items() if ordered else sorted(entries.items()):
        if (
            not single_line(key)
            or not key.strip()
            or key.startswith("#")
            or (not ordered and re.search(r"\s", key))
        ):
            raise ValueError("Invalid lookup key")
        if isinstance(value, list):
            if not all(single_line(part) for part in value):
                raise ValueError("Invalid lookup result")
            value = ", ".join(value)
        if not single_line(value) or not value.strip():
            raise ValueError("Invalid lookup result")
        result[key] = value
    return result


def table_catalog(
    builtins: dict[str, Any], custom: dict[str, Any], native: str
) -> dict[str, Any]:
    """Describe every managed source, its native lookup and its consumer."""
    if native not in SUFFIXES:
        raise ValueError(f"Unsupported native indexed table format {native}")
    if builtins.keys() & custom.keys():
        raise ValueError("A custom table name collides with a built-in table")
    result = {}
    for name, item in (builtins | custom).items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or not isinstance(item, Mapping):
            raise ValueError("Invalid managed table definition")
        if set(item) - {"type", "entries", "parameter", "secret", "aliases", "mode"}:
            raise ValueError(f"Unknown field in table {name}")
        kind = item.get("type", "native")
        kind = native if kind == "native" else kind
        parameter = item.get("parameter", "")
        if kind not in SUFFIXES.keys() | TEXT_TYPES or (
            parameter and not re.fullmatch(r"[a-z][a-z0-9_]*", parameter)
        ):
            raise ValueError(f"Invalid table type or parameter for {name}")
        secret = item.get("secret", False)
        if not isinstance(secret, bool) or not isinstance(item.get("entries"), Mapping):
            raise TypeError(
                f"Table {name} needs a mapping of entries and a boolean secret flag"
            )
        if name in custom and set(item) & {"aliases", "mode"}:
            raise ValueError(
                "Custom table permissions are determined by their secret flag"
            )
        filename = ("custom-" if name in custom else "") + name
        path = f"{DIRECTORY}/{filename}"
        aliases = item.get("aliases", False)
        result[name] = {
            "path": path,
            "map": f"{kind}:{path}",
            "suffix": SUFFIXES.get(kind, ""),
            "secret": secret,
            "mode": "0600" if secret else item.get("mode", "0640"),
            "group": "root" if secret or aliases else "postfix",
            "aliases": aliases,
            "parameter": parameter,
            "entries": table_entries(item["entries"], kind in TEXT_TYPES),
        }
    return result


def map_parameters(
    tables: dict[str, Any],
    backend: str,
    ldap: bool,
    aliases: dict[str, Any],
    policies: list[str],
) -> dict[str, list[str]]:
    """Append lookups after file overrides in the native parameter they serve."""
    result: dict[str, list[str]] = defaultdict(list)
    for table in tables.values():
        if table["parameter"]:
            result[table["parameter"]].append(table["map"])
    if backend != "files":
        for parameter, names in {
            "virtual_mailbox_maps": ["mailboxes"],
            "smtpd_sender_login_maps": ["senders", "alias_domain_senders"],
            "virtual_alias_maps": [
                "virtual_aliases",
                "alias_domains",
                "alias_domain_catchalls",
            ],
        }.items():
            result[parameter].extend(
                f"proxy:{backend}:{DIRECTORY}/{name}.cf" for name in names
            )
    if ldap:
        for parameter, name in [
            ("virtual_mailbox_maps", "mailboxes"),
            ("smtpd_sender_login_maps", "senders"),
        ]:
            result[parameter].append(f"proxy:ldap:{DIRECTORY}/ldap-{name}.cf")
        result["virtual_alias_maps"].extend(
            f"proxy:ldap:{DIRECTORY}/ldap-alias-{name}.cf" for name in aliases
        )
    result["smtp_tls_policy_maps"].extend(policies)
    return dict(result)


def exposed_indexes(tables: dict[str, Any], files: list[dict[str, Any]]) -> list[str]:
    """Restrict an existing index before a public table is rewritten with secrets."""
    private = {
        t["path"] + t["suffix"] for t in tables.values() if t["secret"] and t["suffix"]
    }
    return [
        f["path"]
        for f in files
        if f["path"] in private and (f["mode"] != "0600" or f["uid"] or f["gid"])
    ]


def stale_indexes(
    tables: dict[str, Any], files: list[dict[str, Any]], changed: list[str]
) -> list[dict[str, str]]:
    """Find missing, older or newly rendered indexed tables in one directory scan."""
    existing = {f["path"]: f for f in files}
    indexes = []
    for name, table in tables.items():
        if not table["suffix"]:
            continue
        source = existing.get(table["path"])
        index = existing.get(table["path"] + table["suffix"])
        if (
            name in changed
            or not index
            or (source and index["mtime"] < source["mtime"])
        ):
            indexes.append(
                {
                    "command": "postalias" if table["aliases"] else "postmap",
                    "map": table["map"],
                }
            )
    return indexes


class FilterModule:
    """Expose Postfix-specific lookup filters to the role."""

    @staticmethod
    def obsolete_maps(
        tables: dict[str, Any], files: list[dict[str, Any]], ldap_names: list[str]
    ) -> list[str]:
        """Remove discontinued custom maps, alternate indexes and former LDAP credentials."""
        keep = {t["path"] for t in tables.values()} | {
            t["path"] + t["suffix"] for t in tables.values()
        }
        keep.update(f"{DIRECTORY}/ldap-{name}.cf" for name in ldap_names)
        indexed_names = {
            PurePosixPath(t["path"]).name + ext
            for t in tables.values()
            for ext in SUFFIXES.values()
        }
        return [
            f["path"]
            for f in files
            if f["path"] not in keep
            and (
                PurePosixPath(f["path"]).name.startswith(("custom-", "ldap-"))
                or PurePosixPath(f["path"]).name in indexed_names
            )
            and not f["path"].endswith("~")
        ]

    @classmethod
    def filters(cls) -> dict[str, Any]:
        """Return registered filter names."""
        return {
            "postfix_provider_tables": provider_tables,
            "postfix_table_catalog": table_catalog,
            "postfix_map_parameters": map_parameters,
            "postfix_stale_indexes": stale_indexes,
            "postfix_exposed_indexes": exposed_indexes,
            "postfix_obsolete_maps": cls.obsolete_maps,
        }
