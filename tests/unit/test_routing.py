"""Check relay routing and listener options absent from the SMTP fixtures."""

import unittest

from filter_plugins.postfix_listeners import FilterModule
from filter_plugins.postfix_tables import provider_tables


class RoutingTests(unittest.TestCase):
    """Cover sender-specific credentials and per-listener configuration."""

    def test_shared_provider_endpoint_has_no_ambiguous_password(self) -> None:
        """Fall back to a next-hop password only when a default provider is explicit."""
        providers = [
            {"name": n, "host": "relay.example", "username": n, "password": "pass"}
            for n in ["work", "private"]
        ]
        routes = {"a@example.org": "work", "b@example.org": "private"}
        maps = provider_tables(providers, routes, 587, "", {})
        self.assertEqual(
            maps["sasl_passwd"],
            {"a@example.org": "work:pass", "b@example.org": "private:pass"},
        )
        selected = provider_tables(providers, routes, 587, "work", {})
        self.assertEqual(selected["sasl_passwd"]["[relay.example]:587"], "work:pass")

    def test_ipv4_and_ipv6_bind_independently_but_not_a_wildcard(self) -> None:
        """A wildcard overlaps a specific socket irrespective of declaration order."""
        v4, v6 = {"port": 587, "address": "127.0.0.1"}, {"port": 587, "address": "::1"}
        services = FilterModule.listener_services({"v4": v4, "v6": v6}, "none")
        self.assertEqual(
            [service["bind"] for service in services], ["127.0.0.1:587", "[::1]:587"]
        )
        for pair in [(v4, {"port": 587}), ({"port": 587}, v4)]:
            with (
                self.subTest(pair=pair),
                self.assertRaisesRegex(ValueError, "Overlapping"),
            ):
                FilterModule.listener_services(
                    dict(zip(("first", "second"), pair)), "none"
                )

    def test_listeners_inherit_milter_daemon_name_unless_overridden(self) -> None:
        """MX and submission inherit the global name unless given a listener override."""
        parameter = "milter_macro_daemon_name"
        milters = ["inet:127.0.0.1:11332"]
        services = FilterModule.listener_services(
            {
                "mx": {
                    "port": 25,
                    "mx": True,
                    "tls": "may",
                    "auth": "none",
                    "relay": "none",
                    "milters": milters,
                },
                "submission": {"port": 587, "milters": milters},
                "custom": {
                    "port": 2525,
                    "milters": milters,
                    "options": {parameter: "relay.example.org"},
                },
            },
            "none",
        )
        options = {service["name"]: service["options"] for service in services}
        self.assertNotIn(parameter, options["mx"])
        self.assertNotIn(parameter, options["submission"])
        self.assertEqual(options["custom"][parameter], "relay.example.org")
