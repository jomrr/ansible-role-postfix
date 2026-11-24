#!/usr/bin/env python3
"""Exercise two simultaneously running postscreen listeners and a text ACL update."""

import smtplib
import subprocess
import sys
import time
from pathlib import Path


def connect(port: int) -> smtplib.SMTP:
    """Use a known client address for the CIDR policy."""
    return smtplib.SMTP(
        "127.0.0.1",
        port,
        local_hostname="mx.example.test",
        source_address=("127.0.0.2", 0),
        timeout=12,
    )


def postconf(*args: str) -> list[str]:
    """Read effective native settings from the installed Postfix build."""
    return subprocess.check_output(["postconf", *args], text=True).splitlines()


def allowed() -> None:
    """Require working MX banners, restricted capabilities and a usable cache driver."""
    settings = postconf(
        "-h",
        "smtpd_forbid_unauth_pipelining",
        "smtpd_client_auth_rate_limit",
        "smtpd_client_connection_rate_limit",
        "address_verify_map",
    )
    assert settings[:3] == ["yes", "30", "60"], settings
    assert settings[3].split(":", 1)[0] in postconf("-m"), settings[3]
    actions = postconf(
        "-P",
        "127.0.0.1:2527/inet/postscreen_greet_action",
        "25/inet/postscreen_greet_action",
    )
    assert set(actions) == {
        "25/inet/postscreen_greet_action = enforce",
        "127.0.0.1:2527/inet/postscreen_greet_action = ignore",
    }, actions
    with connect(25) as public, connect(2527) as monitor:
        for client in (public, monitor):
            assert client.ehlo()[0] == 250
            assert not {"etrn", "dsn"}.intersection(client.esmtp_features), (
                client.esmtp_features
            )
            code, detail = client.docmd("ETRN", "example.test")
            assert 500 <= code <= 599, (code, detail)


def denied() -> None:
    """New connections must start seeing the daemon's updated CIDR decision."""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with connect(2527):
                pass
        except smtplib.SMTPConnectError as exc:
            assert exc.smtp_code // 100 == 5, exc
            return
        time.sleep(0.25)
    raise AssertionError("The screened listener still accepts the denied client")


if __name__ == "__main__":
    {"permit": allowed, "reject": denied}[sys.argv[1]]()
    print(Path("/var/spool/postfix/pid/master.pid").read_text(encoding="ascii").strip())
