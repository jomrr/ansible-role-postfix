#!/usr/bin/python
"""Apply one validated Postfix configuration and record successful activation."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any

from ansible.module_utils.basic import AnsibleModule

CONFIG = Path("/etc/postfix")
MAPS = CONFIG / "managed"
RECEIPT = MAPS / ".activation.json"
NAMES = ("main.cf", "master.cf")


@dataclass(frozen=True)
class Generation:
    """The configuration and network policy acknowledged by the last service action."""

    files: str
    digest: str
    network: tuple[str, ...]


EMPTY = Generation("", "", ())


def fingerprint(items: Iterable[tuple[str, bytes]]) -> str:
    """Frame names and content digests so additions, removals and edits are distinct."""
    result = hashlib.sha256()
    for name, data in items:
        result.update(os.fsencode(name) + b"\0" + hashlib.sha256(data).digest())
    return result.hexdigest()


def previous_generation() -> Generation:
    """Treat a missing or damaged acknowledgement as an unconfirmed master."""
    try:
        record = json.loads(RECEIPT.read_bytes())
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError):
        return EMPTY
    if not isinstance(record, dict):
        return EMPTY
    files, digest, network = (record.get(key) for key in ("files", "digest", "network"))
    if (
        not isinstance(files, str)
        or not isinstance(digest, str)
        or not isinstance(network, list)
    ):
        return EMPTY
    if not all(isinstance(value, str) for value in network):
        return EMPTY
    return Generation(files, digest, tuple(network))


@contextmanager
def directory_lock(path: Path) -> Iterator[None]:
    """Serialize publication, the service action and its acknowledgement on this host."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


@contextmanager
def candidate_workspace(
    root: Path, check_mode: bool = False
) -> Iterator[tuple[Path, int]]:
    """Hold the same host lock from allocation through deletion, including check mode."""
    with directory_lock(root):
        abandoned = 0
        for path in root.glob(".candidate-*"):
            # Only reclaim the random names made by tempfile, including earlier role versions.
            if not re.fullmatch(r"\.candidate-[a-z0-9_]{8}", path.name):
                continue
            info = path.lstat()
            if (
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700
            ):
                abandoned += 1
                if not check_mode:
                    shutil.rmtree(path)
        with TemporaryDirectory(dir=root, prefix=".candidate-") as directory:
            yield Path(directory), abandoned


def write_file(module: AnsibleModule, path: Path, data: bytes, mode: int) -> None:
    """Publish a fully written file with the destination's Postfix SELinux context."""
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
            if module.selinux_enabled():
                context = module.selinux_default_context(str(path), stat.S_IFREG)
                module.set_context_if_different(str(temporary), context, False)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def acknowledge(module: AnsibleModule, state: Generation) -> None:
    """Keep even an interrupted correction of previously acknowledged disk drift pending."""
    data = {"files": state.files, "digest": state.digest, "network": state.network}
    write_file(module, RECEIPT, json.dumps(data).encode() + b"\n", 0o600)


def native(module: AnsibleModule, args: list[str]) -> str:
    """Run Postfix or its service manager and propagate a failed validation or action."""
    code, output, error = module.run_command(args)
    if code:
        raise ValueError(
            f"{args[0]} failed ({code}): {error.strip() or output.strip()}"
        )
    return str(output)


def file_contents(path: Path) -> bytes | None:
    """Read regular files only, including an absent target during the first convergence."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Expected a regular Postfix configuration file at {path}")
    return path.read_bytes()


def lookup_digest(module: AnsibleModule, files: str) -> str:
    """Fingerprint desired lookups in bounded memory, including large CIDR lists."""
    inputs = [("configuration", files.encode())]
    for item in module.params["lookup_files"]:
        path = Path(item)
        if path.parent != MAPS:
            raise ValueError(
                "Expected a regular lookup file in the managed Postfix directory"
            )
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError(f"Expected a regular Postfix lookup at {path}")
                digest = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        except FileNotFoundError:
            if module.check_mode:
                continue
            raise
        inputs.append((str(path), digest.digest()))
    return fingerprint(inputs)


def socket_settings(module: AnsibleModule, directory: Path) -> tuple[str, ...]:
    """Read the effective network policy and native inet endpoints from the same pair."""
    config = ["postconf", "-c", str(directory)]
    interfaces = native(
        module,
        [*config, "-hx", "inet_interfaces", "inet_protocols", "master_service_disable"],
    )
    master = native(module, [*config, "-M"])
    endpoints = set()
    for line in master.splitlines():
        if line and not line[0].isspace():
            name, kind, *_ = line.split()
            if kind == "inet":
                endpoints.add(name)
    return (*interfaces.splitlines(), *sorted(endpoints))


def desired_generation(
    module: AnsibleModule, candidate: Path, pair: dict[str, bytes]
) -> Generation:
    """Record effective bind settings alongside the requested configuration."""
    files = fingerprint(pair.items())
    return Generation(
        files, lookup_digest(module, files), socket_settings(module, candidate)
    )


def service_action(module: AnsibleModule, action: str) -> None:
    """Use the platform supervisor, starting an inactive daemon when applying changes."""
    if module.params["service_manager"] == "systemd":
        verb = "reload-or-restart" if action == "reload" else "restart"
        native(module, ["systemctl", verb, "postfix.service"])
    elif action == "reload" and module.run_command(["postfix", "status"])[0]:
        native(module, ["service", "postfix", "start"])
    else:
        native(module, ["service", "postfix", action])


def restore(
    module: AnsibleModule, before: dict[str, bytes | None], changed: list[str]
) -> None:
    """Restore the disk pair if publishing or activating it fails."""
    for name in changed:
        data = before[name]
        if data is None:
            (CONFIG / name).unlink(missing_ok=True)
        else:
            write_file(module, CONFIG / name, data, 0o644)


def network_action(
    module: AnsibleModule, previous: Generation, desired: Generation, disk: str
) -> str:
    """Uncertain or changed socket bindings require starting a new master."""
    if previous.network != desired.network:
        return "restart"
    if previous.files != disk:
        try:
            current = socket_settings(module, CONFIG)
        except ValueError:
            return "restart"
        if current != desired.network:
            return "restart"
    return "reload"


def needs_publication(path: Path, old: bytes | None, new: bytes) -> bool:
    """Restore both content and ownership or permissions of a managed file."""
    if old != new:
        return True
    info = path.stat()
    return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o644)


def activate(module: AnsibleModule, candidate: Path) -> str:
    """Reconcile the desired disk pair and running master while holding the directory lock."""
    pair = {name: (candidate / name).read_bytes() for name in NAMES}
    before = {name: file_contents(CONFIG / name) for name in NAMES}
    changed = [
        name
        for name in NAMES
        if needs_publication(CONFIG / name, before[name], pair[name])
    ]
    previous = previous_generation()
    desired = desired_generation(module, candidate, pair)
    if not changed and previous == desired:
        return "none"
    disk = fingerprint(
        (name, data) for name, data in before.items() if data is not None
    )
    action = network_action(module, previous, desired, disk)
    if module.check_mode:
        return action

    recover_service = disk == previous.files or (
        bool(changed) and module.run_command(["postfix", "status"])[0] == 0
    )
    if module.params["backup"]:
        for name in changed:
            if before[name] is not None:
                module.backup_local(str(CONFIG / name))
    acknowledge(
        module,
        Generation(previous.files, "", previous.network if action == "reload" else ()),
    )
    published = []
    try:
        for name in changed:
            published.append(name)
            write_file(module, CONFIG / name, pair[name], 0o644)
        service_action(module, action)
        native(module, ["postfix", "status"])
    except (OSError, ValueError, SystemExit):
        restore(module, before, published)
        if published and recover_service:
            service_action(module, "restart")
        raise
    if lookup_digest(module, desired.files) != desired.digest:
        raise ValueError(
            "Postfix lookups changed during activation; run the role again"
        )
    acknowledge(module, desired)
    return action


RESTRICTIONS = tuple(
    f"smtpd_{phase}_restrictions"
    for phase in (
        "client",
        "helo",
        "sender",
        "relay",
        "recipient",
        "etrn",
        "data",
        "end_of_data",
    )
)


def discovery(module: AnsibleModule, candidate: Path) -> dict[str, Any]:
    """Use package defaults independently of a possibly damaged live configuration."""
    (candidate / "main.cf").write_text(
        f"inet_interfaces = all\nsetgid_group = {module.params['setgid_group']}\n",
        encoding="utf-8",
    )
    command = ["postconf", "-c", str(candidate)]
    default_map, version, proxy = native(
        module,
        [*command, "-dh", "default_database_type", "mail_version", "proxy_read_maps"],
    ).splitlines()
    return {
        "default_map": default_map,
        "version": version,
        "proxy_maps": proxy,
        "drivers": native(module, [*command, "-m"]).splitlines(),
        "sasl": native(module, [*command, "-a"]).splitlines(),
        "smtp_features": native(
            module,
            [
                *command,
                "-d",
                "smtpd_forbid_bare_newline_reject_code",
                "smtpd_forbid_unauth_pipelining",
            ],
        ),
    }


def assignments(output: str) -> dict[str, str]:
    """Postconf unfolds native values, including empty assignments, to individual lines."""
    result = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key.strip()] = value.strip()
    return result


def effective_policies(
    module: AnsibleModule, candidate: Path
) -> dict[str, dict[str, str]]:
    """Ask Postfix to expand each smtpd's restrictions and named classes in its own scope."""
    command = ["postconf", "-c", str(candidate)]
    config = candidate / "main.cf"
    base = config.read_text(encoding="utf-8")
    result = {}
    for service, overrides in smtpd_overrides(module, command).items():
        # Table values and SASL secrets stay off the command line.
        config.write_text("\n".join([base, *overrides, ""]), encoding="utf-8")
        names = native(module, [*command, "-xh", "smtpd_restriction_classes"])
        classes = names.replace(",", " ").split()
        if any(
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name) for name in classes
        ):
            raise ValueError(f"{service}: invalid smtpd_restriction_classes name")
        values = assignments(native(module, [*command, "-x", *RESTRICTIONS, *classes]))
        values["smtpd_restriction_classes"] = names
        result[service] = values
    return result


def smtpd_overrides(module: AnsibleModule, command: list[str]) -> dict[str, list[str]]:
    """Collect master.cf overrides for smtpd services, including postscreen backends."""
    services: dict[str, list[str]] = {}
    for row in native(module, [*command, "-M"]).splitlines():
        fields = row.split()
        if (
            len(fields) >= 8
            and not row[0].isspace()
            and fields[7].rsplit("/", 1)[-1] == "smtpd"
        ):
            services["/".join(fields[:2])] = []
    for key, value in assignments(native(module, [*command, "-P"])).items():
        service, _, name = key.rpartition("/")
        if service in services:
            services[service].append(f"{name} = {value}")
    return services or {"main.cf": []}


def run_operation(module: AnsibleModule, candidate: Path) -> dict[str, Any]:
    """Use a private native configuration for this single, lock-protected operation."""
    operation = module.params["operation"]
    if operation == "discover":
        return {"changed": False, **discovery(module, candidate)}
    for name in NAMES:
        (candidate / name).write_text(
            module.params["configuration"][name], encoding="utf-8"
        )
    if operation == "validate":
        if module.check_mode:
            native(module, ["postconf", "-c", str(candidate), "-m"])
        else:
            native(module, ["postfix", "-c", str(candidate), "check"])
        return {"changed": False, "policies": effective_policies(module, candidate)}

    indexes = module.params["indexes"]
    if not module.check_mode:
        for index in indexes:
            native(module, [index["command"], "-c", str(candidate), index["map"]])
    action = activate(module, candidate)
    return {"changed": bool(indexes) or action != "none", "action": action}


def main() -> None:
    """Discover, validate or activate without leaving workspaces open between Ansible tasks."""
    module = AnsibleModule(
        argument_spec={
            "operation": {
                "type": "str",
                "choices": ["discover", "validate", "activate"],
                "required": True,
            },
            "setgid_group": {"type": "str"},
            "configuration": {
                "type": "dict",
                "no_log": True,
                "options": {name: {"type": "str", "required": True} for name in NAMES},
            },
            "indexes": {
                "type": "list",
                "elements": "dict",
                "default": [],
                "options": {
                    "command": {
                        "type": "str",
                        "choices": ["postmap", "postalias"],
                        "required": True,
                    },
                    "map": {"type": "str", "required": True},
                },
            },
            "lookup_files": {"type": "list", "elements": "path", "default": []},
            "service_manager": {"type": "str"},
            "backup": {"type": "bool", "default": False},
        },
        required_if=[
            ("operation", "discover", ["setgid_group"]),
            ("operation", "validate", ["configuration"]),
            ("operation", "activate", ["configuration", "service_manager"]),
        ],
        supports_check_mode=True,
    )
    try:
        with candidate_workspace(CONFIG, module.check_mode) as (candidate, abandoned):
            result = run_operation(module, candidate)
            result["changed"] = result["changed"] or abandoned > 0
    except (OSError, ValueError) as exc:
        module.fail_json(msg=str(exc))
    else:
        module.exit_json(**result)


if __name__ == "__main__":
    main()
