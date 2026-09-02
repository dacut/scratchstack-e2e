"""
Tests that action names are matched without regard to case.

IAM compares the Action element case-insensitively, on the service prefix and
on the API name alike: a statement granting ``iam:getuser`` reaches a GetUser
request, and one granting ``IAM:GetUser`` does too. Policy authors rely on this
without saying so -- AWS's own documentation and console spell actions in mixed
case, while plenty of hand-written and generated policies do not -- so a policy
that reads as a grant has to behave as one whatever case it was written in.

Three directions, because they fail differently and only one of them fails
safe:

    Action      a differently-cased grant that does not match denies a call
                the policy plainly intends to allow. Annoying, and visible the
                first time someone runs it.

    NotAction   a differently-cased exclusion that does not match *allows* a
                call the policy plainly intends to exclude. NotAction inverts
                a non-match, so a matcher that is too strict here is a matcher
                that grants too much, and nothing about the policy document
                looks wrong.

    Deny        a differently-cased deny that does not match allows a call the
                policy explicitly forbids. The same failure as NotAction,
                reached by the clause people trust most.

Each test carries controls in both directions. A grant spelled exactly as the
API is named proves the document is live and the probes work -- without it, a
test that denied everything would pass its denial assertions for the wrong
reason. An action the document never mentions proves the grant is not simply
covering everything.

The wildcard case is exercised separately from the literal one because they are
not the same comparison: a pattern such as ``iam:listsaml*`` is globbed against
the request's API name, while ``iam:listusers`` is compared to it whole. An
implementation can easily fold case in one path and not the other.

One way these can fail without answering the question: if the service rejects a
miscased action at PutUserPolicy time rather than accepting it and matching it
later, the failure surfaces as MalformedPolicyDocument out of the fixture, not
as an assertion. That is still an answer -- the spelling never reaches the
matcher -- but it is a different one, so read the error before concluding the
matcher is at fault.

Deliberately not tested here: whether the *resource* ARN is matched
case-insensitively. It is not, and that is a separate question with a different
answer -- ARNs are case-sensitive in their resource portion.

Ordering follows the rest of the suite: the allowed cases first, retried until
the grant is in effect, and only then the denials, which by that point can only
be the matcher talking rather than a grant that has not propagated.
"""

from logging import getLogger

from scratchstack_e2e.aspen import AuthzTestCase, allow, deny, policy, statement

log = getLogger(__name__)

#: Grants whose action is spelled in some case other than the one IAM names the
#: API with, each paired with a probe for that API and a note on what varies.
#:
#: Every entry names a distinct action, so an entry that matches for the wrong
#: reason cannot be masked by another entry's grant. All are unparameterized
#: reads: nothing here depends on a resource existing, so a failure is the
#: matcher and not a missing fixture.
MISCASED_GRANTS = [
    (
        "iam:listusers",
        lambda iam: iam.list_users(MaxItems=1),
        "action name lowercased",
    ),
    (
        "iam:LISTGROUPS",
        lambda iam: iam.list_groups(MaxItems=1),
        "action name uppercased",
    ),
    (
        "IAM:ListRoles",
        lambda iam: iam.list_roles(MaxItems=1),
        "service prefix uppercased",
    ),
    (
        "iam:listPOLICIES",
        lambda iam: iam.list_policies(MaxItems=1),
        "case varying within the action name",
    ),
    (
        "iam:listsaml*",
        lambda iam: iam.list_saml_providers(),
        "lowercased, reached through a wildcard",
    ),
]

#: An action spelled exactly as IAM names it. Granted alongside the miscased
#: ones so that its succeeding separates "the document has propagated and the
#: probes work" from "the matcher accepted the spelling".
CONTROL_ACTION = "iam:ListAccountAliases"


def control_probe(iam):
    """The probe for CONTROL_ACTION."""
    return iam.list_account_aliases()


#: An action no document below ever mentions, in any case. Its being denied is
#: what rules out a grant that has quietly widened to everything -- without it,
#: a matcher that ignored the Action element entirely would pass every
#: assertion in the first test.
def ungranted_probe(iam):
    """A probe for an action that is never granted."""
    return iam.list_open_id_connect_providers()


class TestActionNameCase(AuthzTestCase):
    """
    Tests that action names are matched without regard to case.
    """

    def test_action_grants_regardless_of_case(self):
        """
        Test that an Action element reaches a request whose API differs from it
        only in case.

        The subject is granted six actions: five spelled in some case other
        than IAM's own, and one spelled exactly. Each is probed by the API it
        names. The exactly-spelled one running first establishes that the
        document is in effect, so a later denial is the spelling and not
        propagation.
        """
        subject = self.subject(
            permissions=policy(
                allow(action=CONTROL_ACTION),
                *(allow(action=action) for action, _, _ in MISCASED_GRANTS),
            )
        )
        iam = subject.client("iam")

        # The control first: until it passes, every call is denied for want of
        # a policy at all and nothing below would mean anything.
        log.info("Probing the control grant %s", CONTROL_ACTION)
        self.assertAllowed(
            lambda: control_probe(iam),
            f"{CONTROL_ACTION} is spelled exactly as IAM names it and must be allowed; "
            "the inline policy has not taken effect",
        )

        for action, probe, varies in MISCASED_GRANTS:
            with self.subTest(action=action):
                log.info("Probing %s (%s)", action, varies)
                self.assertAllowed(
                    lambda: probe(iam),
                    f"the policy grants {action!r} ({varies}), which names the same "
                    "action as the request; action names are matched without regard "
                    "to case",
                )

        # Nothing in the document mentions this one, so a matcher that had
        # widened to everything would be caught here rather than passing.
        log.info("Probing an action the document never grants")
        self.assertDenied(
            lambda: ungranted_probe(iam),
            "no statement grants iam:ListOpenIDConnectProviders in any case",
        )

    def test_not_action_excludes_regardless_of_case(self):
        """
        Test that a NotAction element excludes a request whose API differs from
        it only in case.

        This is the direction that fails open. NotAction applies to everything
        it does *not* name, so an exclusion that fails to match is an exclusion
        that grants: a matcher too strict to see ``iam:listusers`` as ListUsers
        would allow the very call the statement was written to withhold.
        """
        subject = self.subject(
            permissions=policy(
                statement("Allow", not_action="iam:listusers", resource="*")
            )
        )
        iam = subject.client("iam")

        # Anything outside the exclusion is granted, so this doubles as the
        # propagation probe.
        log.info("Probing an action outside the NotAction")
        self.assertAllowed(
            lambda: iam.list_roles(MaxItems=1),
            "NotAction covers every action it does not name, so iam:ListRoles "
            "must be allowed; the inline policy has not taken effect",
        )

        log.info("Probing the action the NotAction excludes, differently cased")
        self.assertDenied(
            lambda: iam.list_users(MaxItems=1),
            "the statement excludes 'iam:listusers', which names the same action "
            "as the request; a NotAction that fails to match grants the call it "
            "was written to withhold",
        )

    def test_deny_matches_regardless_of_case(self):
        """
        Test that a Deny element matches a request whose API differs from it
        only in case.

        The same failure as NotAction, reached through the clause an author is
        most likely to be relying on: a deny that does not match is a deny that
        does not deny, and the broad allow it was written to carve out of stays
        in force.
        """
        subject = self.subject(
            permissions=policy(
                allow(action="iam:*"),
                deny(action="iam:listusers"),
            )
        )
        iam = subject.client("iam")

        # The broad allow is what the deny carves out of; its succeeding shows
        # the document is live and that a denial below is the deny statement.
        log.info("Probing an action the deny does not name")
        self.assertAllowed(
            lambda: iam.list_roles(MaxItems=1),
            "iam:* grants iam:ListRoles and no statement denies it; the inline "
            "policy has not taken effect",
        )

        log.info("Probing the denied action, differently cased")
        self.assertDenied(
            lambda: iam.list_users(MaxItems=1),
            "the statement denies 'iam:listusers', which names the same action as "
            "the request; an explicit deny that fails to match leaves the broad "
            "allow it was written to carve out of in force",
        )
