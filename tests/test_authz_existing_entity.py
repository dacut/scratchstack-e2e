"""
Tests for the condition keys operations on an *existing* entity supply.

The create operations derive their condition keys from the request. These four
derive them from the entity being acted on, which the service has to look up
before it can authorize the call: the tags on the entity back aws:ResourceTag/{}
and iam:ResourceTag/{}, and the managed policy serving as its permissions
boundary backs iam:PermissionsBoundary.

    DeleteRole                     tags + boundary
    DeleteRolePolicy               tags + boundary
    DeleteUserPermissionsBoundary  tags + boundary
    DeleteUserPolicy               tags + boundary
    CreateAccessKey                tags only
    UpdateAccessKey                tags only
    DeleteAccessKey                tags only

The access key operations act on a user and read its tags, but IAM defines no
iam:PermissionsBoundary for them, so only the two resource-tag spellings are
asserted there. There is no DeactivateAccessKey API to test: the only
Deactivate* operation IAM has is DeactivateMFADevice, and deactivating a key is
UpdateAccessKey with Status=Inactive, which is what test_update_access_key
does.

Every key an operation is said to supply is asserted for it. The stakes are not symmetric: a *missing*
key leaves a guard dormant that should have fired, while a *spurious* one makes
a StringNotEquals deny guard fire where IAM leaves it dormant, changing the
meaning of a policy an operator already wrote. Scratchstack supplies all three
for these four operations, and this file is what says so on the strength of
IAM's behavior rather than its documentation -- which has already proved wrong
twice, in both directions, for the policy APIs.

Each test issues the same operation against four entities under one grant whose
statements are scoped by entity ARN, so exactly one statement can account for
each outcome:

    named_aws   allowed only if aws:ResourceTag/{} is supplied
    named_iam   allowed only if iam:ResourceTag/{} is supplied
    named_pb    allowed only if iam:PermissionsBoundary is supplied
    other       denied, showing the conditions are evaluated rather than ignored

The three named entities are identical -- the keys cannot be told apart by the
state of an entity, since two of them read the same tags -- so they are told
apart by which statement reaches them.

DeleteRole is the only one of the four that destroys its target. Its fixture is
told so once the call succeeds, since a fixture asked to delete a role that is
already gone spends its whole retry budget on NoSuchEntity first -- which is
the right behavior in general, a newly created role being briefly invisible,
and so the caller's job to prevent. The other three leave their entity standing
and need no such handoff.

The allow side tolerates any non-AccessDenied outcome. What is under test is
whether authorization passed, and some of these operations can fail afterwards
for unrelated reasons: DeleteRole reports DeleteConflict for a role that still
has something attached, and the authorization decision has already been made by
then. Retrying while denied also absorbs the grant's propagation delay, so the
denial asserted last cannot be a not-yet-live grant.
"""

import time
from json import dumps
from logging import getLogger

from botocore.exceptions import ClientError

from scratchstack_e2e import IamTestCase, Policy, Role, User
from scratchstack_e2e.arn import Arn
from scratchstack_e2e.aspen import allow, policy, trust_policy
from scratchstack_e2e.retry import (EVENTUAL_BACKOFF_MULTIPLIER,
                                    EVENTUAL_INIT_BACKOFF,
                                    EVENTUAL_MAX_BACKOFF, EVENTUAL_TIMEOUT,
                                    eventually, eventually_client_error)

log = getLogger(__name__)

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
            if code != "AccessDenied":
                log.info("Not denied: the call failed with %s instead", code)
                return e
            if time.monotonic() >= deadline:
                raise
            log.info("Still AccessDenied; will retry in %s seconds", interval)
            time.sleep(interval)
            interval = min(interval * EVENTUAL_BACKOFF_MULTIPLIER, EVENTUAL_MAX_BACKOFF)


class TestExistingEntityConditions(IamTestCase):
    """
    Tests for the condition keys operations on an existing entity supply.
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

    def tag_checks(self, entities):
        """
        The two resource-tag spellings, one entity apiece.

        Both read the same tags, so no entity state can tell them apart; they
        are told apart by which statement reaches which entity.
        """
        return [
            (f"aws:ResourceTag/{TAG_KEY}", TAG_VALUE, entities[0]),
            (f"iam:ResourceTag/{TAG_KEY}", TAG_VALUE, entities[1]),
        ]

    def tag_and_boundary_checks(self, entities, boundary_arn):
        """
        The two resource-tag spellings plus iam:PermissionsBoundary.
        """
        return self.tag_checks(entities) + [
            ("iam:PermissionsBoundary", boundary_arn, entities[2]),
        ]

    def assert_keys_govern(self, action, checks, other, invoke):
        """
        Assert that `action` supplies each condition key in `checks`.

        `checks` pairs each key and the value it should carry with the entity
        the grant reaches through it, via a statement scoped to that entity's
        ARN and conditioned on that key alone -- so exactly one statement can
        account for each allow. `other` is an entity a statement names with a
        tag value it does not carry; its denial is what shows the conditions
        are evaluated rather than ignored. `invoke` performs the operation
        against one entity as the subject.
        """
        grant = policy(
            *[
                allow(
                    action=action,
                    resource=entity.arn,
                    condition={"StringEquals": {key: value}},
                )
                for key, value, entity in checks
            ],
            # Named, but with a tag value the entity does not carry. Its being
            # denied is what shows the conditions are evaluated at all.
            allow(
                action=action,
                resource=other.arn,
                condition={"StringEquals": {f"aws:ResourceTag/{TAG_KEY}": TAG_VALUE}},
            ),
            # Granted unconditionally as a propagation probe.
            allow(action=["iam:ListRoles", "iam:ListUsers"], resource="*"),
        )

        with User(self.iam, permissions=grant) as subject:
            iam = subject.client("iam")
            eventually(lambda: iam.list_users(MaxItems=1))

            for key, _value, entity in checks:
                with self.subTest(condition_key=key):
                    log.info("Expecting %s to be allowed by %s", action, key)
                    eventually_not_denied(lambda: invoke(iam, entity))

            with self.subTest(condition_key="non-matching value"):
                log.info("Expecting %s to be denied on the non-matching entity", action)
                eventually_client_error(
                    "AccessDenied", lambda: invoke(iam, other)
                )

    def test_delete_role(self):
        """
        Test that DeleteRole supplies all three entity-derived condition keys.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [self.target_role(TAG_VALUE, boundary.arn) for _ in range(3)]
        other = self.target_role(OTHER_TAG_VALUE, other_boundary.arn)

        def invoke(iam, role):
            log.info("Attempting to delete role %s", role.role_name)
            iam.delete_role(RoleName=role.role_name)
            # This is the one operation here that destroys its target, so
            # ownership has to be handed back. Until this line the fixture
            # still cleans the role up -- on a denial, or on a DeleteConflict,
            # or if the test fails first. After it, there is nothing to clean
            # up, and a teardown that tried anyway would retry NoSuchEntity
            # for the whole budget before giving up.
            role.forget()

        self.assert_keys_govern(
            "iam:DeleteRole",
            self.tag_and_boundary_checks(named, boundary.arn),
            other,
            invoke,
        )

    def test_delete_role_policy(self):
        """
        Test that DeleteRolePolicy supplies all three entity-derived condition
        keys. The keys describe the role, not the inline policy being removed.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [
            self.target_role(TAG_VALUE, boundary.arn, with_inline_policy=True)
            for _ in range(3)
        ]
        other = self.target_role(
            OTHER_TAG_VALUE, other_boundary.arn, with_inline_policy=True
        )

        def invoke(iam, role):
            log.info("Attempting to delete inline policy on role %s", role.role_name)
            iam.delete_role_policy(
                RoleName=role.role_name, PolicyName=INLINE_POLICY_NAME
            )

        self.assert_keys_govern(
            "iam:DeleteRolePolicy",
            self.tag_and_boundary_checks(named, boundary.arn),
            other,
            invoke,
        )

    def test_delete_user_permissions_boundary(self):
        """
        Test that DeleteUserPermissionsBoundary supplies all three
        entity-derived condition keys.

        iam:PermissionsBoundary is the interesting one here: it names the
        boundary already set on the user, which is the very thing the call
        removes. That is what lets a policy delegate boundary management while
        confining it to entities under a particular boundary.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [self.target_user(TAG_VALUE, boundary.arn) for _ in range(3)]
        other = self.target_user(OTHER_TAG_VALUE, other_boundary.arn)

        def invoke(iam, user):
            log.info("Attempting to delete boundary on user %s", user.user_name)
            iam.delete_user_permissions_boundary(UserName=user.user_name)

        self.assert_keys_govern(
            "iam:DeleteUserPermissionsBoundary",
            self.tag_and_boundary_checks(named, boundary.arn),
            other,
            invoke,
        )

    def test_delete_user_policy(self):
        """
        Test that DeleteUserPolicy supplies all three entity-derived condition
        keys. The keys describe the user, not the inline policy being removed.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [
            self.target_user(TAG_VALUE, boundary.arn, with_inline_policy=True)
            for _ in range(3)
        ]
        other = self.target_user(
            OTHER_TAG_VALUE, other_boundary.arn, with_inline_policy=True
        )

        def invoke(iam, user):
            log.info("Attempting to delete inline policy on user %s", user.user_name)
            iam.delete_user_policy(
                UserName=user.user_name, PolicyName=INLINE_POLICY_NAME
            )

        self.assert_keys_govern(
            "iam:DeleteUserPolicy",
            self.tag_and_boundary_checks(named, boundary.arn),
            other,
            invoke,
        )

    # ------------------------------------------------------------------
    # Access keys
    #
    # These act on an access key but are authorized against the user that owns
    # it, so the condition keys describe the user. IAM defines no
    # iam:PermissionsBoundary for them, so the targets carry tags alone and
    # only the two resource-tag spellings are asserted.
    # ------------------------------------------------------------------

    def access_key_targets(self):
        """
        Two users the grant reaches, one per resource-tag spelling, and one it
        does not. Each carries an access key of its own, created by the
        fixture.
        """
        named = [self.target_user(TAG_VALUE) for _ in range(2)]
        other = self.target_user(OTHER_TAG_VALUE)
        return named, other

    def test_create_access_key(self):
        """
        Test that CreateAccessKey supplies both resource-tag spellings from the
        user the key is being created for.
        """
        named, other = self.access_key_targets()

        def invoke(iam, user):
            log.info("Attempting to create an access key for user %s", user.user_name)
            iam.create_access_key(UserName=user.user_name)

        self.assert_keys_govern(
            "iam:CreateAccessKey", self.tag_checks(named), other, invoke
        )

    def test_update_access_key(self):
        """
        Test that UpdateAccessKey supplies both resource-tag spellings from the
        user owning the key.

        This is also the deactivation case: IAM has no DeactivateAccessKey, and
        a key is deactivated by updating its status to Inactive.
        """
        named, other = self.access_key_targets()

        def invoke(iam, user):
            log.info("Attempting to deactivate the access key of user %s", user.user_name)
            iam.update_access_key(
                UserName=user.user_name,
                AccessKeyId=user.credentials["AccessKeyId"],
                Status="Inactive",
            )

        self.assert_keys_govern(
            "iam:UpdateAccessKey", self.tag_checks(named), other, invoke
        )

    def test_delete_access_key(self):
        """
        Test that DeleteAccessKey supplies both resource-tag spellings from the
        user owning the key.

        The key goes away but the user does not, so no ownership handoff is
        needed: the fixture finds no keys left to remove and deletes the user
        as usual.
        """
        named, other = self.access_key_targets()

        def invoke(iam, user):
            log.info("Attempting to delete the access key of user %s", user.user_name)
            iam.delete_access_key(
                UserName=user.user_name,
                AccessKeyId=user.credentials["AccessKeyId"],
            )

        self.assert_keys_govern(
            "iam:DeleteAccessKey", self.tag_checks(named), other, invoke
        )
