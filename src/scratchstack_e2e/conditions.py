#!/usr/bin/env python3
"""
Machinery for asking which condition keys an IAM operation supplies.

An operation's request context is not observable directly: the only way to ask
whether a key is there is to write a policy that turns on it and see which way
the evaluator goes. Every check here is therefore a statement scoped to its own
entity ARN and conditioned on one key alone, so exactly one statement can
account for each outcome.

Both directions are needed. An allow alone cannot tell a key that is present
from a condition that is being ignored; a denial alone cannot tell a key that
is absent from a grant that has not propagated yet. The allows are asserted
first and retried until they pass, which is what makes the denials that follow
attributable to the condition.
"""

import time
from collections import namedtuple
from json import dumps
from logging import getLogger

from botocore.exceptions import ClientError

from .arn import Arn
from .aspen import allow, policy, trust_policy
from .case import IamTestCase
from .group import Group
from .policy import Policy
from .retry import (EVENTUAL_BACKOFF_MULTIPLIER, EVENTUAL_INIT_BACKOFF,
                    EVENTUAL_MAX_BACKOFF, EVENTUAL_TIMEOUT, eventually,
                    eventually_client_error)
from .role import Role
from .user import User

log = getLogger(__name__)

Check = namedtuple("Check", "label condition entity")

#: The tag the resource-tag conditions are written against.
TAG_KEY = "TestTag1"
TAG_VALUE = "TestValue1"
OTHER_TAG_VALUE = "SomeOtherValue"

#: The name of the inline policy the DeleteRolePolicy/DeleteUserPolicy tests
#: delete off their targets.
INLINE_POLICY_NAME = "scratchstack-test-inline"

#: A valid document, for the inline policies and the boundary policies alike.
#: None of these tests care what any of them says.
SOME_DOCUMENT = policy(allow(action="s3:GetObject", resource="*"))

#: A second document, for the extra policy version DeletePolicyVersion removes.
SECOND_DOCUMENT = policy(allow(action="s3:PutObject", resource="*"))

#: What AWS allows an inline user policy to hold. The subject's grant is one,
#: and exceeding this reports LimitExceeded from PutUserPolicy -- an error that
#: says nothing about which assertion grew too large, hence the check below.
INLINE_POLICY_LIMIT = 2048

#: Failures that happen before the evaluator ever runs. Tolerating these in an
#: allow assertion would let it pass against a service that does not implement
#: the operation, or against a request too malformed to authorize -- the test
#: would report that a condition key is supplied without having asked.
NEVER_AUTHORIZED_CODES = frozenset(
    (
        "InvalidAction",
        "InvalidClientTokenId",
        "MalformedInput",
        "SignatureDoesNotMatch",
        "ValidationError",
    )
)


def eventually_not_denied(probe, *, timeout=EVENTUAL_TIMEOUT):
    """
    Call `probe` until it is not refused by the authorization evaluator.

    Returns once the call succeeds or fails for any reason other than
    AccessDenied: what is under test is whether authorization passed, and an
    operation can still fail afterwards on its own terms -- DeleteRole reports
    DeleteConflict for a role with something attached, by which point the
    authorization decision has already been made.

    Retrying while denied is also what absorbs the propagation delay on a
    freshly attached grant, so a denial asserted after this has returned cannot
    be a grant that had not arrived yet.
    """
    deadline = time.monotonic() + timeout
    interval = EVENTUAL_INIT_BACKOFF
    while True:
        try:
            return probe()
        except ClientError as e:
            error = e.response.get("Error")
            assert isinstance(error, dict)
            code = error.get("Code")
            if code in NEVER_AUTHORIZED_CODES:
                raise AssertionError(
                    f"{code} means the request never reached the authorization "
                    f"evaluator, so this proves nothing about the condition "
                    f"keys the operation supplies. For InvalidAction the "
                    f"service does not implement the operation at all."
                ) from e
            if code != "AccessDenied":
                log.info("Not denied: the call failed with %s instead", code)
                return e
            if time.monotonic() >= deadline:
                raise
            log.info("Still AccessDenied; will retry in %s seconds", interval)
            time.sleep(interval)
            interval = min(interval * EVENTUAL_BACKOFF_MULTIPLIER, EVENTUAL_MAX_BACKOFF)


class ConditionTestCase(IamTestCase):
    """
    Base case for tests that ask which condition keys an operation supplies.

    Subclasses build targets with the target_* helpers and assert against them
    with assert_conditions or assert_operations.
    """

    def setUp(self):
        super().setUp()
        identity = eventually(self.sts.get_caller_identity)
        self.identity_arn = Arn.parse(identity["Arn"])
        self.trust = trust_policy(
            f"arn:{self.identity_arn.partition}:iam::"
            f"{self.identity_arn.account_id}:root"
        )

    def boundary_policy(self):
        """
        A managed policy to serve as a permissions boundary on a target.
        """
        return self.fixture(Policy(self.iam, SOME_DOCUMENT))

    def target_role(self, tag_value, boundary_arn, *, with_inline_policy=False):
        """
        A role carrying the given tag value and permissions boundary, created
        and torn down as the admin principal.
        """
        role = self.fixture(
            Role(
                self.iam,
                self.trust,
                tags={TAG_KEY: tag_value},
                permissions_boundary=boundary_arn,
            )
        )
        if with_inline_policy:
            eventually(
                lambda: self.iam.put_role_policy(
                    RoleName=role.role_name,
                    PolicyName=INLINE_POLICY_NAME,
                    PolicyDocument=dumps(SOME_DOCUMENT),
                )
            )
        return role

    def target_user(self, tag_value, boundary_arn=None, *, with_inline_policy=False):
        """
        A user carrying the given tag value and permissions boundary, created
        and torn down as the admin principal.
        """
        user = self.fixture(
            User(
                self.iam,
                tags={TAG_KEY: tag_value},
                permissions_boundary=boundary_arn,
            )
        )
        if with_inline_policy:
            eventually(
                lambda: self.iam.put_user_policy(
                    UserName=user.user_name,
                    PolicyName=INLINE_POLICY_NAME,
                    PolicyDocument=dumps(SOME_DOCUMENT),
                )
            )
        return user

    @staticmethod
    def supplied(key, value, entity):
        """
        A check that `key` is supplied carrying `value`: the statement matches
        only if it is, so the operation must be allowed on `entity`.
        """
        return Check(f"{key} supplied", {"StringEquals": {key: value}}, entity)

    @staticmethod
    def absent(key, entity):
        """
        A check that `key` is not supplied at all. Null matches only a key that
        is missing, so the operation must be allowed on `entity`.

        Pair this with `mismatched` on a second entity. On its own an allow
        here says the key is absent, but only the denial rules out the
        condition being ignored altogether.
        """
        return Check(f"{key} absent", {"Null": {key: "true"}}, entity)

    @staticmethod
    def mismatched(key, value, entity):
        """
        A statement naming `entity` under a value it does not carry -- or under
        a key it does not have at all. Either way it cannot match, so the
        operation must be denied.
        """
        return Check(f"{key} does not match", {"StringEquals": {key: value}}, entity)

    def mismatched_tag(self, entity):
        """
        The usual denial: an entity named under a tag value it does not carry.
        """
        return self.mismatched(f"aws:ResourceTag/{TAG_KEY}", TAG_VALUE, entity)

    def tag_checks(self, entities):
        """
        The two resource-tag spellings, one entity apiece.

        Both read the same tags, so no entity state can tell them apart; they
        are told apart by which statement reaches which entity.
        """
        return [
            self.supplied(f"aws:ResourceTag/{TAG_KEY}", TAG_VALUE, entities[0]),
            self.supplied(f"iam:ResourceTag/{TAG_KEY}", TAG_VALUE, entities[1]),
        ]

    def tag_and_boundary_checks(self, entities, boundary_arn):
        """
        The two resource-tag spellings plus iam:PermissionsBoundary.
        """
        return self.tag_checks(entities) + [
            self.supplied("iam:PermissionsBoundary", boundary_arn, entities[2]),
        ]

    def target_policy(self, tag_value, *, with_extra_version=False):
        """
        A managed policy carrying the given tag value, created and torn down as
        the admin principal.
        """
        created = self.fixture(
            Policy(self.iam, SOME_DOCUMENT, tags={TAG_KEY: tag_value})
        )
        if with_extra_version:
            # A non-default version, so DeletePolicyVersion has something to
            # remove that is not the default one it is forbidden to touch.
            arn = created.arn
            if arn is not None:
                eventually(
                    lambda: self.iam.create_policy_version(
                        PolicyArn=arn,
                        PolicyDocument=dumps(SECOND_DOCUMENT),
                    )
                )
        return created

    def target_group(self, *, with_inline_policy=False):
        """
        A group, created and torn down as the admin principal.

        Groups take no tags -- IAM has no group-tagging operation -- so unlike
        the other targets here they are told apart only by their ARNs.
        """
        group = self.fixture(Group(self.iam))
        if with_inline_policy:
            eventually(
                lambda: self.iam.put_group_policy(
                    GroupName=group.group_name,
                    PolicyName=INLINE_POLICY_NAME,
                    PolicyDocument=dumps(SOME_DOCUMENT),
                )
            )
        return group

    def assert_operations(self, operations, allowed, denied):
        """
        Assert what each of `operations` supplies, under a single grant.

        `operations` pairs an action with the callable that performs it against
        one entity. Read-only operations leave their targets intact, so several
        can share one set of targets and one subject principal rather than
        paying the credential-propagation wait per action.

        The checks apply to every operation: each contributes one statement per
        action, scoped to its entity ARN and conditioned on its key alone.
        """
        checks = list(allowed) + list(denied)
        actions = [action for action, _invoke in operations]
        grant = policy(
            # One statement per check, naming every action at once, rather than
            # one per action-and-check pair. The isolation is the same -- each
            # entity belongs to exactly one check, so an allow on it can only
            # come from that check's statement -- but the document stays inside
            # the 2048-byte cap AWS puts on an inline user policy, which the
            # pairwise form blew past at five actions.
            *[
                allow(
                    action=actions,
                    resource=check.entity.arn,
                    condition=check.condition,
                )
                for check in checks
            ],
            # Granted unconditionally as a propagation probe.
            allow(
                action=[
                    "iam:ListGroups",
                    "iam:ListPolicies",
                    "iam:ListRoles",
                    "iam:ListUsers",
                ],
                resource="*",
            ),
        )

        # Each entity must belong to exactly one check. Two statements naming
        # the same entity both apply to a call against it, so an allow in one
        # would satisfy a request the other was meant to refuse -- the denial
        # would fail with the call having succeeded, saying nothing about the
        # key under test.
        seen = {}
        for check in checks:
            owner = seen.setdefault(id(check.entity), check.label)
            if owner != check.label:
                raise AssertionError(
                    f"{check.label!r} and {owner!r} name the same entity. Each "
                    f"check needs an entity of its own, or the statements will "
                    f"overlap and the outcome will not isolate either key."
                )

        size = len(dumps(grant, separators=(",", ":")))
        if size > INLINE_POLICY_LIMIT:
            raise AssertionError(
                f"The grant for {actions} is {size} bytes, over the "
                f"{INLINE_POLICY_LIMIT}-byte limit on an inline user policy. "
                f"Split the operations across more than one assertion."
            )

        with User(self.iam, permissions=grant) as subject:
            iam = subject.client("iam")
            eventually(lambda: iam.list_users(MaxItems=1))

            for action, invoke in operations:
                for check in allowed:
                    with self.subTest(action=action, check=check.label):
                        log.info("Expecting %s to be allowed: %s", action, check.label)
                        eventually_not_denied(lambda: invoke(iam, check.entity))

                for check in denied:
                    with self.subTest(action=action, check=check.label):
                        log.info("Expecting %s to be denied: %s", action, check.label)
                        eventually_client_error(
                            "AccessDenied", lambda: invoke(iam, check.entity)
                        )

    def assert_conditions(self, action, allowed, denied, invoke):
        """
        Assert what `action` supplies, one condition key at a time.

        Every check contributes a statement scoped to its own entity ARN and
        conditioned on that key alone, so exactly one statement can account for
        each outcome. Checks in `allowed` must let the operation through;
        checks in `denied` must not. `invoke` performs the operation against
        one entity as the subject.

        Both lists matter. An allow alone cannot tell a key that is present
        from a condition that is being ignored, and a denial alone cannot tell
        a key that is absent from a grant that has not propagated -- which is
        why the allows run first, retried until the grant is live.
        """
        self.assert_operations([(action, invoke)], allowed, denied)
