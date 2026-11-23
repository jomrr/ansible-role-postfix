#!/usr/bin/env python3
"""Exercise real Postfix/Dovecot delivery against two isolated TLS provider fixtures."""

from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
import smtplib
import socket
import socketserver
import ssl
import subprocess
import threading
from typing import BinaryIO, cast
import uuid

from smtp_client import in_mailbox, message, submission, tls_connection, wait_for


@dataclass
class Provider:
    """Authentication contract and captured deliveries of one provider."""

    username: str
    password: str
    wrapper: bool
    tls: ssl.SSLContext
    messages: list[bytes] = field(default_factory=list)
    deferred: bool = False


class RelayServer(socketserver.ThreadingTCPServer):
    """Loopback-only provider with a deterministic temporary delivery failure."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port: int, provider: Provider) -> None:
        self.provider = provider
        super().__init__(("127.0.0.1", port), RelayHandler)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(20)
        if self.provider.wrapper:
            connection = self.provider.tls.wrap_socket(connection, server_side=True)
        return connection, address


class RelayHandler(socketserver.BaseRequestHandler):
    """Implement only the SMTP commands used by the Postfix client."""

    def __init__(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
        server: socketserver.BaseServer,
    ) -> None:
        self.connection = request
        self.stream: BinaryIO = self.connection.makefile("rb")
        self.encrypted = cast(RelayServer, server).provider.wrapper
        self.authenticated = False
        super().__init__(request, client_address, server)

    def handle(self) -> None:
        self.reply(b"220 localhost fixture")
        try:
            while line := self.stream.readline():
                command, _, argument = line.rstrip(b"\r\n").partition(b" ")
                if not self.dispatch(command.upper(), argument):
                    break
        finally:
            self.stream.close()
            self.connection.close()

    def reply(self, response: bytes) -> None:
        """Send one SMTP response."""
        self.connection.sendall(response + b"\r\n")

    def dispatch(self, command: bytes, argument: bytes) -> bool:
        """Process a single SMTP command and indicate whether to continue."""
        provider = cast(RelayServer, self.server).provider
        if command == b"EHLO":
            self.reply(b"250-localhost")
            self.reply(b"250-AUTH PLAIN" if self.encrypted else b"250-STARTTLS")
            self.reply(b"250 SIZE 10240000")
        elif command == b"STARTTLS":
            self.reply(b"220 Ready for TLS")
            self.stream.close()
            self.connection = provider.tls.wrap_socket(
                self.connection, server_side=True
            )
            self.stream = self.connection.makefile("rb")
            self.encrypted = True
        elif command == b"AUTH":
            self.authenticate(argument, provider)
        elif command == b"MAIL":
            self.reply(
                b"250 Sender accepted"
                if self.authenticated
                else b"530 Authentication required"
            )
        elif command == b"RCPT":
            if b"retry@" in argument and not provider.deferred:
                provider.deferred = True
                self.reply(b"450 Temporary fixture failure")
            else:
                self.reply(b"250 Recipient accepted")
        elif command == b"DATA":
            self.receive_message(provider)
        elif command == b"QUIT":
            self.reply(b"221 Bye")
            return False
        else:
            self.reply(b"250 OK")
        return True

    def authenticate(self, argument: bytes, provider: Provider) -> None:
        """Require the configured credentials over verified client-side TLS."""
        mechanism, _, encoded = argument.partition(b" ")
        if not encoded:
            self.reply(b"334 ")
            encoded = self.stream.readline().strip()
        expected = (provider.username.encode(), provider.password.encode())
        parts = base64.b64decode(encoded).split(b"\0")
        self.authenticated = (
            self.encrypted and mechanism == b"PLAIN" and tuple(parts[-2:]) == expected
        )
        self.reply(
            b"235 Authenticated" if self.authenticated else b"535 Invalid credentials"
        )

    def receive_message(self, provider: Provider) -> None:
        """Capture one complete SMTP DATA body."""
        self.reply(b"354 End with a dot")
        lines: list[bytes] = []
        while line := self.stream.readline():
            if line == b".\r\n":
                break
            lines.append(line)
        provider.messages.append(b"".join(lines))
        self.reply(b"250 Stored")


def in_provider(provider: Provider, token: str) -> bool:
    """Find a message captured by a specific authenticated provider."""
    return any(token.encode() in mail for mail in provider.messages)


def fetch_connection(
    context: ssl.SSLContext,
    trusted_reception: bool,
    source_address: tuple[str, int] | None = None,
) -> smtplib.SMTP:
    """Use the explicitly selected Fetchmail authentication policy."""
    if trusted_reception:
        client = smtplib.SMTP(
            "localhost", 2525, timeout=10, source_address=source_address
        )
        client.ehlo()
    else:
        client = tls_connection(context, 2525, source_address)
        client.login("alice@example.test", "alice-secret")
    return client


def verify_authentication(context: ssl.SSLContext) -> None:
    """Require encryption and authentication on every enabled port by default."""
    for port in (25, 1588, 1466, 2525):
        if port != 1466:
            with smtplib.SMTP("localhost", port, timeout=10) as client:
                client.ehlo()
                assert not client.has_extn("auth"), (
                    f"AUTH advertised before TLS on {port}"
                )
                assert client.mail("sender@outside.test")[0] == 530, port
        with tls_connection(context, port) as client:
            assert client.mail("sender@outside.test")[0] == 250
            assert client.rcpt("bob@example.test")[0] >= 500, (
                f"Unauthenticated local delivery accepted on {port}"
            )
    with tls_connection(context, 1588) as client:
        try:
            client.login("alice@example.test", "wrong-password")
        except smtplib.SMTPAuthenticationError:
            pass
        else:
            raise AssertionError("Wrong password accepted")


def verify_trusted_reception(context: ssl.SSLContext) -> None:
    """Explicit authentication exceptions must still prevent relaying and spoofing."""
    with smtplib.SMTP(
        "localhost", 25, local_hostname="mx.outside.test", timeout=10
    ) as client:
        client.ehlo()
        assert client.mail("sender@outside.test")[0] == 250
        assert client.rcpt("sink@outside.test")[0] >= 500, (
            "Unauthenticated relay accepted"
        )
        for sender in ("alice@example.test", "directory@example.test"):
            client.rset()
            assert client.mail(sender)[0] == 250
            code, response = client.rcpt("bob@example.test")
            assert code >= 500 and b"requires authenticated submission" in response
        client.rset()
        token = uuid.uuid4().hex
        client.send_message(
            message("sender@outside.test", "directory@example.test", token)
        )
    wait_for(lambda: in_mailbox("directory", token), "LDAP mailbox delivery failed")
    with submission(context, "bob") as client:
        client.mail("bob@example.test")
        assert client.rcpt("sink@outside.test")[0] == 250
    verify_fetch_policy(context, trusted_reception=True)
    with fetch_connection(context, trusted_reception=True) as client:
        client.send_message(
            message("sender@outside.test", "bob@example.test", token + "fetch")
        )
    wait_for(
        lambda: in_mailbox("bob", token + "fetch"), "Unauthenticated Fetchmail failed"
    )


def verify_sender_ownership(context: ssl.SSLContext, ports: tuple[int, ...]) -> None:
    """Reject both another account's identity and unassigned sender addresses."""
    for port in ports:
        with submission(context, "alice", port) as client:
            client.mail("bob@example.test")
            assert client.rcpt("sink@outside.test")[0] >= 500, "Foreign sender accepted"
            client.rset()
            client.mail("unassigned@example.test")
            assert client.rcpt("sink@outside.test")[0] >= 500, (
                "Unassigned sender accepted"
            )


def verify_fetch_policy(context: ssl.SSLContext, trusted_reception: bool) -> None:
    """Constrain even authenticated fetchers to trusted sources and local recipients."""
    with fetch_connection(context, trusted_reception, ("127.0.0.2", 0)) as client:
        assert client.mail("sender@outside.test")[0] == 250
        assert client.rcpt("bob@example.test")[0] >= 500, (
            "Untrusted Fetchmail source accepted"
        )
    with fetch_connection(context, trusted_reception) as client:
        assert client.mail("sender@outside.test")[0] == 250
        assert client.rcpt("sink@outside.test")[0] >= 500, "Fetchmail relay accepted"


def verify_local_sender() -> None:
    """Enforce Unix-user sender permissions through the actual postdrop helper."""
    denied = subprocess.run(
        [
            "runuser",
            "-u",
            "postfix_test",
            "--",
            "/usr/sbin/sendmail",
            "-f",
            "alice@example.test",
            "bob@example.test",
        ],
        input=b"Subject: forbidden sender\n\nrejected\n",
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert denied.returncode != 0, "Local sendmail sender impersonation accepted"


def verify_accounts(context: ssl.SSLContext) -> None:
    """Exercise SQL-backed sender ownership, shared aliases and alias-domain delivery."""
    token = uuid.uuid4().hex
    for user in ("alice", "bob"):
        with submission(context, user) as client:
            client.send_message(
                message("sales@example.test", "sales@example.test", token + user)
            )
        for recipient in ("alice", "bob"):
            wait_for(
                partial(in_mailbox, recipient, token + user),
                f"Shared sender or alias fan-out failed for {user} to {recipient}",
            )
    with submission(context, "alice") as client:
        client.send_message(
            message("alice@alias.test", "alice@alias.test", token + "domain")
        )
    wait_for(
        lambda: in_mailbox("alice", token + "domain"), "Alias domain delivery failed"
    )


def verify_delivery(context: ssl.SSLContext, providers: list[Provider]) -> None:
    """Check separate provider credentials, retries, aliases and archive copies."""
    token = uuid.uuid4().hex
    for index, user in enumerate(("alice", "bob")):
        marker = token + user
        with submission(context, user, port=(1588, 1466)[index]) as client:
            client.send_message(
                message(f"{user}@example.test", "sink@outside.test", marker)
            )
        wait_for(
            partial(in_provider, providers[index], marker),
            "Provider delivery failed",
        )
        assert all(
            marker.encode() not in mail for mail in providers[1 - index].messages
        ), "Wrong provider selected"
    wait_for(
        lambda: in_mailbox("archive", token + "alice"), "Outgoing archive copy missing"
    )
    with submission(context, "alice", port=25) as client:
        client.send_message(
            message("alice@example.test", "sink@outside.test", token + "smtp")
        )
    wait_for(
        partial(in_provider, providers[0], token + "smtp"), "Port 25 submission failed"
    )
    with submission(context, "alice") as client:
        client.send_message(
            message("sales@example.test", "retry@outside.test", token + "retry")
        )
    wait_for(
        lambda: any(
            (token + "retry").encode() in mail for mail in providers[0].messages
        ),
        "Automatic retry failed",
    )
    assert providers[0].deferred, "Temporary delivery failure was not exercised"
    with fetch_connection(context, trusted_reception=False) as client:
        client.send_message(
            message("sender@outside.test", "bob@example.test", token + "incoming")
        )
        client.send_message(
            message("sender@outside.test", "sales@example.test", token + "alias")
        )
    wait_for(
        lambda: in_mailbox("bob", token + "incoming"),
        "Fetchmail to LMTP delivery failed",
    )
    wait_for(
        lambda: in_mailbox("archive", token + "incoming"),
        "Incoming archive copy missing",
    )
    wait_for(
        lambda: (
            in_mailbox("alice", token + "alias") and in_mailbox("bob", token + "alias")
        ),
        "Alias fan-out failed",
    )
    subprocess.run(
        [
            "runuser",
            "-u",
            "postfix_test",
            "--",
            "/usr/sbin/sendmail",
            "-f",
            "local@example.test",
            "bob@example.test",
        ],
        input=message(
            "local@example.test", "bob@example.test", token + "local"
        ).as_bytes(),
        capture_output=True,
        check=True,
        timeout=10,
    )
    wait_for(
        lambda: in_mailbox("bob", token + "local"), "Authorized local submission failed"
    )


def main() -> None:
    """Run isolated provider fixtures while exercising the configured mail service."""
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--trusted-reception", action="store_true")
    modes.add_argument("--accounts", action="store_true")
    modes.add_argument("--null-client", action="store_true")
    args = parser.parse_args()
    client_tls = ssl.create_default_context(cafile="/etc/postfix-test/server.crt")
    if args.accounts:
        verify_accounts(client_tls)
        return
    if args.trusted_reception:
        verify_trusted_reception(client_tls)
        return
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.minimum_version = ssl.TLSVersion.TLSv1_2
    server_tls.load_cert_chain(
        "/etc/postfix-test/server.crt", "/etc/postfix-test/server.key"
    )
    providers = [
        Provider("provider-a", "relay-a-secret", False, server_tls),
        Provider("provider-b", "relay-b-secret", True, server_tls),
    ]
    with ExitStack() as stack:
        for port, provider in zip(
            (1587, 1465), providers[:1] if args.null_client else providers
        ):
            server = stack.enter_context(RelayServer(port, provider))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(thread.join, 5)
            stack.callback(server.shutdown)
        if args.null_client:
            marker = uuid.uuid4().hex
            subprocess.run(
                ["sendmail", "-f", "local@node.example.test", "sink@outside.test"],
                input=message(
                    "local@node.example.test", "sink@outside.test", marker
                ).as_bytes(),
                check=True,
            )
            wait_for(
                lambda: in_provider(providers[0], marker),
                "Authenticated null-client relay failed",
            )
            return
        verify_authentication(client_tls)
        verify_sender_ownership(client_tls, (25, 1588, 1466))
        verify_fetch_policy(client_tls, trusted_reception=False)
        verify_local_sender()
        verify_delivery(client_tls, providers)
    log = Path("/var/log/postfix.log").read_text(encoding="utf-8")
    assert "status=sent" in log and "reject:" in log, (
        "Delivery or rejection logging missing"
    )
    print(
        "TLS, Dovecot SASL/LMTP, sender ownership, local submission, "
        "both relay modes, retries and archive copies passed"
    )


if __name__ == "__main__":
    main()
