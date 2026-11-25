#!/usr/bin/env python3
"""Exercise the role through native queue, SMTP, Sieve and lookup interfaces."""

from __future__ import annotations

import argparse
import json
import queue
import smtplib
import socket
import socketserver
import ssl
import subprocess
import threading
import uuid
from collections.abc import Callable
from email.utils import make_msgid
from functools import partial
from pathlib import Path

from smtp_client import in_mailbox, message, submission, wait_for

MAPS = Path("/etc/postfix/managed")
TESTS = Path("/etc/postfix-test")


def command(*args: str) -> str:
    """Read the output of a successful native command."""
    return subprocess.check_output(args, text=True).strip()


def closed() -> None:
    """Local-only mode has no TCP services and logs through syslog."""
    assert not any(
        row.split()[1] == "inet" for row in command("postconf", "-M").splitlines()
    )
    assert command("postconf", "-h", "maillog_file") == ""
    assert command("postconf", "-h", "mailbox_size_limit") == "51200000"
    assert not Path("/etc/logrotate.d/ansible-postfix").exists()
    assert not any(MAPS.glob("sasl_passwd.*~"))
    assert not any(MAPS.glob("*.cf.*~"))
    command("postfix", "status")


def bounce() -> None:
    """A locally submitted external address must generate a permanent local DSN."""
    closed()
    identifier = uuid.uuid4().hex
    local = "root@localhost." + command("postconf", "-h", "mydomain")
    recipient = identifier + "@outside.test"
    subprocess.run(
        ["sendmail", "-f", local, "--", recipient],
        input=message(local, recipient, identifier).as_bytes(),
        check=True,
    )
    wait_for(
        lambda: any(
            p.is_file()
            and recipient.encode() in p.read_bytes()
            and b"5.7.1" in p.read_bytes()
            for p in [Path("/var/mail/root"), Path("/var/spool/mail/root")]
        ),
        "No permanent local bounce for the foreign recipient",
    )


def recovery(pid: str, map_type: str) -> None:
    """Verify recovered native maps without interrupting the master process."""
    assert command("cat", "/var/spool/postfix/pid/master.pid") == pid
    assert command("postconf", "-h", "myhostname") == socket.getfqdn()
    assert any(
        "abuse: postmaster" in backup.read_text(encoding="utf-8").splitlines()
        for backup in MAPS.glob("local_aliases.*~")
    ), "The previous local aliases were not backed up"
    assert (
        command("postalias", "-q", "monitoring", f"{map_type}:{MAPS}/local_aliases")
        == "root"
    )
    ext = {"hash": ".db", "btree": ".db", "lmdb": ".lmdb", "cdb": ".cdb"}[map_type]
    for name in ("mailboxes", "sasl_passwd"):
        assert (MAPS / (name + ext)).stat().st_mtime_ns >= (
            MAPS / name
        ).stat().st_mtime_ns


def envelopes(cases: list[tuple[int, str, str, str, int]]) -> None:
    """Check RCPT decisions after successful authentication."""
    context = ssl.create_default_context(cafile=str(TESTS / "server.crt"))
    for port, user, sender, recipient, expected in cases:
        with submission(context, user, port) as client:
            assert client.mail(sender)[0] == 250
            code, detail = client.rcpt(recipient)
            assert code // 100 == expected, (
                port,
                user,
                sender,
                recipient,
                code,
                detail,
            )


def directory(cases: list[tuple[int, str, str, str, int]]) -> None:
    """Verify SASL entitlement and actual file, LDAP alias and group expansion."""
    envelopes(cases)
    context = ssl.create_default_context(cafile=str(TESTS / "server.crt"))
    with submission(context, "alice") as client:
        for alias, recipient in (
            ("file-only", "bob"),
            ("alternate", "directory"),
            ("list", "directory"),
        ):
            marker = uuid.uuid4().hex
            client.send_message(
                message("directory@example.test", alias + "@example.test", marker)
            )
            wait_for(
                partial(in_mailbox, recipient, marker),
                f"Alias {alias} did not deliver to {recipient}",
            )


class Sink(socketserver.StreamRequestHandler):
    """Capture cleartext gateway deliveries routed to the configured next hop."""

    received: queue.Queue[bytes] = queue.Queue()

    def handle(self) -> None:
        self.wfile.write(b"220 gateway.example.test ESMTP\r\n")
        while raw := self.rfile.readline():
            verb = raw.split(maxsplit=1)[0].upper()
            if verb == b"DATA":
                self.wfile.write(b"354 Continue\r\n")
                body = []
                while (line := self.rfile.readline()) not in (b".\r\n", b""):
                    body.append(line)
                self.received.put(b"".join(body))
            if verb == b"QUIT":
                self.wfile.write(b"221 Bye\r\n")
                return
            self.wfile.write(b"250 OK\r\n")


class GatewayServer(socketserver.ThreadingTCPServer):
    """Allow a fresh fixture to reuse the loopback port."""

    allow_reuse_address = True


def submission_overrides() -> str:
    """Record only the master's overrides for the independent submission service."""
    return "\n".join(
        row
        for row in command("postconf", "-P").splitlines()
        if row.startswith("1588/inet/")
    )


def gateway(domain: str) -> None:
    """Exercise the public MX, listed gateway recipients and restricted relay."""
    assert command("postconf", "-h", "mailbox_size_limit") == "10240000"
    (TESTS / "submission-overrides").write_text(
        submission_overrides(), encoding="utf-8"
    )
    marker = uuid.uuid4().hex
    with GatewayServer(("127.0.0.1", 1590), Sink) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with smtplib.SMTP(
                "localhost",
                25,
                local_hostname="mx.outside.test",
                source_address=("127.0.0.2", 0),
                timeout=15,
            ) as client:
                client.ehlo()
                client.mail(f"sender@{domain}")
                assert client.rcpt(f"unknown@{domain}")[0] == 550
                client.rset()
                client.send_message(
                    message(f"sender@{domain}", f"known@{domain}", marker)
                )
            assert marker.encode() in Sink.received.get(timeout=30)
            with smtplib.SMTP("localhost", 2526, timeout=10) as client:
                client.mail("blocked@outside.test")
                assert client.rcpt("sink@outside.test")[0] >= 500
                client.rset()
                client.send_message(
                    message(
                        "application@example.test", "sink@outside.test", marker + "relay"
                    )
                )
            assert (marker + "relay").encode() in Sink.received.get(timeout=30)
            with smtplib.SMTP(
                "localhost", 2526, source_address=("127.0.0.2", 0), timeout=10
            ) as client:
                client.mail("application@example.test")
                assert client.rcpt("sink@outside.test")[0] >= 500
        finally:
            server.shutdown()
            thread.join()


def vacation(user: str) -> None:
    """Observe a real Sieve vacation reply delivered into the original sender's mailbox."""
    identifier = make_msgid(domain="example.test")
    request = message(
        f"{user}@example.test", "bob@example.test", "Postfix vacation test"
    )
    request["Message-ID"] = identifier
    with smtplib.SMTP("localhost", 2525, timeout=10) as client:
        client.send_message(request)
    wait_for(
        partial(in_mailbox, user, "Postfix vacation reply", in_reply_to=identifier),
        f"No Sieve vacation reply to {identifier} delivered to {user}",
    )


def hub() -> None:
    """Unchanged submission overrides still enforce the new global outbound policy."""
    assert submission_overrides() == (TESTS / "submission-overrides").read_text(
        encoding="utf-8"
    )
    envelopes(
        [
            (1588, "alice", "alice@example.test", "sink@outside.test", 5),
            (1588, "alice", "alice@example.test", "bob@example.test", 2),
        ]
    )
    with socket.socket() as sock:
        assert sock.connect_ex(("127.0.0.1", 2526)) != 0


def main() -> None:
    """Select the check belonging to the current installed operating mode."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "closed",
            "bounce",
            "recovery",
            "envelopes",
            "directory",
            "gateway",
            "vacation",
            "hub",
        ),
    )
    parser.add_argument("--pid", default="")
    parser.add_argument("--map-type", default="")
    parser.add_argument("--cases", type=json.loads)
    parser.add_argument("--user", default="")
    parser.add_argument("--domain", default="")
    args = parser.parse_args()
    checks: dict[str, Callable[[], None]] = {
        "closed": closed,
        "bounce": bounce,
        "recovery": lambda: recovery(args.pid, args.map_type),
        "envelopes": lambda: envelopes(args.cases),
        "directory": lambda: directory(args.cases),
        "gateway": lambda: gateway(args.domain),
        "vacation": lambda: vacation(args.user),
        "hub": hub,
    }
    checks[args.mode]()


if __name__ == "__main__":
    main()
