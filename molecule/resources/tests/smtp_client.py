"""SMTP, TLS and maildir helpers shared by the Molecule operating modes."""

from __future__ import annotations

import smtplib
import ssl
import time
from collections.abc import Callable
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from pathlib import Path


def wait_for(predicate: Callable[[], bool], description: str) -> None:
    """Wait for asynchronous delivery without forcing a queue flush."""
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise AssertionError(description)


def in_mailbox(user: str, token: str, *, in_reply_to: str = "") -> bool:
    """Find a uniquely identifiable delivery in the account's Dovecot maildir."""
    mailbox = Path(f"/var/lib/postfix-test/mail/{user}@example.test/mail")
    for sub in ("new", "cur"):
        for path in (mailbox / sub).glob("*"):
            data = path.read_bytes()
            if token.encode() in data and (
                not in_reply_to
                or BytesHeaderParser().parsebytes(data).get("In-Reply-To")
                == in_reply_to
            ):
                return True
    return False


def message(sender: str, recipient: str, token: str) -> EmailMessage:
    """Build a uniquely identifiable fixture message."""
    mail = EmailMessage()
    mail["From"] = sender
    mail["To"] = recipient
    mail["Subject"] = token
    mail.set_content(token)
    return mail


def tls_connection(
    context: ssl.SSLContext, port: int, source_address: tuple[str, int] | None = None
) -> smtplib.SMTP:
    """Establish a verified TLS connection on a configured SMTP listener."""
    client: smtplib.SMTP
    if port == 1466:
        client = smtplib.SMTP_SSL(
            "localhost",
            port,
            timeout=10,
            context=context,
            source_address=source_address,
        )
    else:
        client = smtplib.SMTP(
            "localhost", port, timeout=10, source_address=source_address
        )
        client.starttls(context=context)
    client.ehlo()
    return client


def submission(context: ssl.SSLContext, user: str, port: int = 1588) -> smtplib.SMTP:
    """Authenticate against the real Dovecot socket through Postfix."""
    client = tls_connection(context, port)
    client.login(f"{user}@example.test", f"{user}-secret")
    return client
