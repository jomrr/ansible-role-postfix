"""Cover the restriction grammar independently of a running SMTP server."""

import unittest

from filter_plugins.postfix_restrictions import FilterModule


class RestrictionTests(unittest.TestCase):
    """Exercise spelling, arguments and class scope in expanded Postfix settings."""

    def test_argument_boundaries_and_class_chains(self) -> None:
        """Named classes can chain and map/policy arguments can contain commas and spaces."""
        settings = {
            "smtpd_restriction_classes": "internal, downstream",
            "internal": "check_sender_access { proxy:ldap:/etc/postfix/senders.cf }, downstream",
            "downstream": (
                "warn_if_reject REJECT_UNVERIFIED_RECIPIENT, "
                "reject_rbl_client zone.example=127.0.0.2"
            ),
            "smtpd_recipient_restrictions": (
                "internal check_policy_service { inet:127.0.0.1:10023, "
                "default_action={451 policy busy} }, "
                "inline:{ { user@example.org=OK }, { admin@example.org=REJECT } }, permit"
            ),
        }
        self.assertTrue(FilterModule.valid_restrictions({"submission/inet": settings}))

    def test_unknown_names_are_checked_even_after_permit(self) -> None:
        """An early accept in a live SMTP session cannot hide a misspelled rule in a class."""
        with self.assertRaisesRegex(
            ValueError,
            r"25/inet downstream: unknown SMTP restriction 'reject_unverifed_recipient'",
        ):
            FilterModule.valid_restrictions(
                {
                    "25/inet": {
                        "smtpd_restriction_classes": "downstream",
                        "downstream": "permit, reject_unverifed_recipient",
                        "smtpd_recipient_restrictions": "downstream",
                    }
                }
            )

    def test_classes_are_local_to_each_service(self) -> None:
        """A declaration on another listener cannot make a misspelled class callable."""
        with self.assertRaisesRegex(
            ValueError, "587/inet.*unknown SMTP restriction 'internal'"
        ):
            FilterModule.valid_restrictions(
                {
                    "25/inet": {
                        "smtpd_restriction_classes": "internal",
                        "internal": "permit",
                    },
                    "587/inet": {
                        "smtpd_restriction_classes": "",
                        "smtpd_recipient_restrictions": "internal",
                    },
                }
            )

    def test_invalid_operands_and_class_definitions(self) -> None:
        """Report malformed explicit maps and classes that would fail during a delivery."""
        for rule in [
            "check_recipient_access",
            "check_sasl_access permit",
            "REJECT_SENDER_LOGIN_MISMATCH",
            "sleep reject",
            "check_policy_service { unix:socket",
        ]:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                FilterModule.valid_restrictions(
                    {
                        "mx": {
                            "smtpd_restriction_classes": "",
                            "smtpd_sender_restrictions": rule,
                        }
                    }
                )
        for settings in [{"a": ""}, {"a": "b", "b": "a"}]:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                FilterModule.valid_restrictions(
                    {
                        "mx": {
                            "smtpd_restriction_classes": ", ".join(settings),
                            **settings,
                        }
                    }
                )

    def test_restrictions_removed_in_postfix_39(self) -> None:
        """Check retired names against the installed package's native generation."""
        policy = {
            "mx": {
                "smtpd_restriction_classes": "",
                "smtpd_recipient_restrictions": "check_relay_domains",
            }
        }
        self.assertTrue(FilterModule.valid_restrictions(policy, pre_39=True))
        with self.assertRaisesRegex(ValueError, "removed in Postfix 3.9"):
            FilterModule.valid_restrictions(policy)
