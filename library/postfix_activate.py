#!/usr/bin/python
"""Apply one validated Postfix configuration and record successful activation."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from tempfile import NamedTemporaryFile

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


def main() -> None:
    """Run activation with check-mode support."""
    module = AnsibleModule(
        argument_spec={
            "candidate": {"type": "path", "required": True},
            "lookup_files": {"type": "list", "elements": "path", "required": True},
            "service_manager": {"type": "str", "required": True},
            "backup": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
    )
    try:
        candidate = Path(module.params["candidate"])
        if candidate.parent != CONFIG or not candidate.name.startswith(".candidate-"):
            raise ValueError("Expected a private candidate directory in /etc/postfix")
        with directory_lock(CONFIG):
            action = activate(module, candidate)
    except (OSError, ValueError) as exc:
        module.fail_json(msg=str(exc))
    else:
        module.exit_json(changed=action != "none", action=action)


if __name__ == "__main__":
    main()
