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
    DeleteUser                     tags only -- boundary asserted absent
    DeletePolicy                   tags only
    DeletePolicyVersion            tags only
    CreateAccessKey                tags only
    UpdateAccessKey                tags only
    DeleteAccessKey                tags only
    DeleteGroup                    nothing at all
    DeleteGroupPolicy              nothing at all

The access key operations act on a user and read its tags, but IAM defines no
iam:PermissionsBoundary for them, so only the two resource-tag spellings are
asserted there. There is no DeactivateAccessKey API to test: the only
Deactivate* operation IAM has is DeactivateMFADevice, and deactivating a key is
UpdateAccessKey with Status=Inactive, which is what test_update_access_key
does.

Every key an operation is said to supply is asserted for it, and where a key is
said *not* to be supplied that is asserted too -- DeleteUser withholding
iam:PermissionsBoundary, and the group operations supplying nothing. An absence
is asserted from both sides: Null matches only a key that is missing and must
be allowed, while StringEquals cannot match one and must be denied. Neither
half suffices alone, since an allow cannot tell a present key from an ignored
condition and a denial cannot tell an absent key from an unpropagated grant.

The DeleteUser case turns on a detail worth stating: every target carries a
permissions boundary. Against a user with none the key would be missing for
want of a value rather than because the operation withholds it, and the test
would pass without having looked at the question. The stakes are not symmetric: a *missing*
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

from logging import getLogger

from scratchstack_e2e import Policy
from scratchstack_e2e.conditions import (INLINE_POLICY_NAME, OTHER_TAG_VALUE,
                                         SOME_DOCUMENT, TAG_KEY, TAG_VALUE,
                                         Check, ConditionTestCase)
from scratchstack_e2e.retry import eventually

log = getLogger(__name__)


class TestExistingEntityConditions(ConditionTestCase):
    """
    Tests for the condition keys operations on an existing entity supply.
    """

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

        self.assert_conditions(
            "iam:DeleteRole",
            self.tag_and_boundary_checks(named, boundary.arn),
            [self.mismatched_tag(other)],
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

        self.assert_conditions(
            "iam:DeleteRolePolicy",
            self.tag_and_boundary_checks(named, boundary.arn),
            [self.mismatched_tag(other)],
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

        self.assert_conditions(
            "iam:DeleteUserPermissionsBoundary",
            self.tag_and_boundary_checks(named, boundary.arn),
            [self.mismatched_tag(other)],
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

        self.assert_conditions(
            "iam:DeleteUserPolicy",
            self.tag_and_boundary_checks(named, boundary.arn),
            [self.mismatched_tag(other)],
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

        self.assert_conditions(
            "iam:CreateAccessKey",
            self.tag_checks(named),
            [self.mismatched_tag(other)],
            invoke,
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
            log.info(
                "Attempting to deactivate the access key of user %s", user.user_name
            )
            iam.update_access_key(
                UserName=user.user_name,
                AccessKeyId=user.credentials["AccessKeyId"],
                Status="Inactive",
            )

        self.assert_conditions(
            "iam:UpdateAccessKey",
            self.tag_checks(named),
            [self.mismatched_tag(other)],
            invoke,
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

        self.assert_conditions(
            "iam:DeleteAccessKey",
            self.tag_checks(named),
            [self.mismatched_tag(other)],
            invoke,
        )

    # ------------------------------------------------------------------
    # The remaining delete operations
    # ------------------------------------------------------------------

    def test_delete_user(self):
        """
        Test that DeleteUser supplies both resource-tag spellings and *not*
        iam:PermissionsBoundary.

        The documentation lists the boundary key for the operations that change
        what an entity may do, but not for deleting one. That absence is
        asserted here rather than assumed, because the same documentation has
        already proved wrong twice for the policy APIs -- and in this direction
        the error is the damaging one: a boundary key supplied where IAM
        supplies none makes a StringNotEquals deny guard fire on a policy an
        operator already wrote.

        Every target carries a boundary, which is what makes the assertion mean
        anything. Against a user with no boundary the key would be missing for
        want of a value rather than because the operation withholds it, and the
        test would pass without having looked at the question.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [self.target_user(TAG_VALUE, boundary.arn) for _ in range(3)]
        pb_named = self.target_user(TAG_VALUE, boundary.arn)
        other = self.target_user(OTHER_TAG_VALUE, other_boundary.arn)

        def invoke(iam, user):
            log.info("Attempting to delete user %s", user.user_name)
            iam.delete_user(UserName=user.user_name)
            # Ownership handoff, as for DeleteRole: the fixture cleans up right
            # until the delete succeeds, and not after.
            user.forget()

        self.assert_conditions(
            "iam:DeleteUser",
            self.tag_checks(named) + [self.absent("iam:PermissionsBoundary", named[2])],
            [
                # The boundary is set on this user, so a supplied key would
                # match and let the call through. It must not.
                self.mismatched("iam:PermissionsBoundary", boundary.arn, pb_named),
                self.mismatched_tag(other),
            ],
            invoke,
        )

    def test_delete_policy(self):
        """
        Test that DeletePolicy supplies both resource-tag spellings from the
        policy being deleted.
        """
        named = [self.target_policy(TAG_VALUE) for _ in range(2)]
        other = self.target_policy(OTHER_TAG_VALUE)

        def invoke(iam, managed_policy):
            log.info("Attempting to delete policy %s", managed_policy.arn)
            iam.delete_policy(PolicyArn=managed_policy.arn)
            managed_policy.forget()

        self.assert_conditions(
            "iam:DeletePolicy",
            self.tag_checks(named),
            [self.mismatched_tag(other)],
            invoke,
        )

    def test_delete_policy_version(self):
        """
        Test that DeletePolicyVersion supplies both resource-tag spellings.

        The keys describe the policy, not the version being removed. The policy
        survives, so no ownership handoff is needed; the fixture finds one
        version left and deletes the policy as usual.
        """
        named = [
            self.target_policy(TAG_VALUE, with_extra_version=True) for _ in range(2)
        ]
        other = self.target_policy(OTHER_TAG_VALUE, with_extra_version=True)

        def invoke(iam, managed_policy):
            log.info("Attempting to delete a version of policy %s", managed_policy.arn)
            iam.delete_policy_version(PolicyArn=managed_policy.arn, VersionId="v2")

        self.assert_conditions(
            "iam:DeletePolicyVersion",
            self.tag_checks(named),
            [self.mismatched_tag(other)],
            invoke,
        )

    def test_delete_group(self):
        """
        Test that DeleteGroup supplies no request context at all.

        Groups are not taggable and are not principals, so there is nothing for
        a condition key to describe. As with CreateGroup, that is asserted from
        both sides rather than assumed: Null matches only a key that is absent
        and must be allowed, StringEquals cannot match one and must be denied,
        and an unconditioned statement proves the grant is live before either
        is read as evidence.
        """
        unconditioned = self.target_group()
        null_checked = self.target_group()
        other = self.target_group()
        tag_key = f"aws:ResourceTag/{TAG_KEY}"

        def invoke(iam, group):
            log.info("Attempting to delete group %s", group.group_name)
            iam.delete_group(GroupName=group.group_name)
            group.forget()

        self.assert_conditions(
            "iam:DeleteGroup",
            [
                Check("no condition at all", None, unconditioned),
                self.absent(tag_key, null_checked),
            ],
            [self.mismatched(tag_key, TAG_VALUE, other)],
            invoke,
        )

    def test_delete_group_policy(self):
        """
        Test that DeleteGroupPolicy supplies no request context either.

        The inline policy goes away but the group does not, so no ownership
        handoff is needed.
        """
        unconditioned = self.target_group(with_inline_policy=True)
        null_checked = self.target_group(with_inline_policy=True)
        other = self.target_group(with_inline_policy=True)
        tag_key = f"aws:ResourceTag/{TAG_KEY}"

        def invoke(iam, group):
            log.info("Attempting to delete inline policy on group %s", group.group_name)
            iam.delete_group_policy(
                GroupName=group.group_name, PolicyName=INLINE_POLICY_NAME
            )

        self.assert_conditions(
            "iam:DeleteGroupPolicy",
            [
                Check("no condition at all", None, unconditioned),
                self.absent(tag_key, null_checked),
            ],
            [self.mismatched(tag_key, TAG_VALUE, other)],
            invoke,
        )

    # ------------------------------------------------------------------
    # Detaching a managed policy
    #
    # iam:PolicyARN names the policy the request is detaching, so unlike every
    # other key here it comes from the request rather than from the entity.
    # Each target carries its own attached policy, recorded on the fixture as
    # `attached_arn` for the detach call to name.
    # ------------------------------------------------------------------

    def attachable_policy(self):
        """A managed policy for attaching to, and detaching from, a target."""
        return self.fixture(Policy(self.iam, SOME_DOCUMENT))

    def attached(self, entity, managed_policy, attacher, **target):
        """
        Attach `managed_policy` to `entity` as the admin principal, recording
        the ARN on the fixture so the detach call can name it.
        """
        eventually(
            lambda: attacher(PolicyArn=managed_policy.arn, **target)
        )
        entity.attached_arn = managed_policy.arn
        return entity

    def attached_group(self, managed_policy):
        group = self.target_group()
        return self.attached(
            group, managed_policy, self.iam.attach_group_policy,
            GroupName=group.group_name,
        )

    def attached_role(self, tag_value, boundary_arn, managed_policy):
        role = self.target_role(tag_value, boundary_arn)
        return self.attached(
            role, managed_policy, self.iam.attach_role_policy,
            RoleName=role.role_name,
        )

    def attached_user(self, tag_value, boundary_arn, managed_policy):
        user = self.target_user(tag_value, boundary_arn)
        return self.attached(
            user, managed_policy, self.iam.attach_user_policy,
            UserName=user.user_name,
        )

    def test_detach_group_policy(self):
        """
        Test that DetachGroupPolicy supplies iam:PolicyARN, and that it is
        compared against the policy the request names.

        A group is neither taggable nor a principal, so the policy being
        detached is the only thing a condition here can describe. The second
        group carries a different policy, so a statement conditioned on the
        first ARN cannot match its request -- which is what shows the key is
        compared rather than merely present.
        """
        wanted = self.attachable_policy()
        unwanted = self.attachable_policy()
        named = self.attached_group(wanted)
        other = self.attached_group(unwanted)

        def invoke(iam, group):
            log.info(
                "Attempting to detach %s from group %s",
                group.attached_arn,
                group.group_name,
            )
            iam.detach_group_policy(
                GroupName=group.group_name, PolicyArn=group.attached_arn
            )

        self.assert_conditions(
            "iam:DetachGroupPolicy",
            [self.supplied("iam:PolicyARN", wanted.arn, named)],
            [self.mismatched("iam:PolicyARN", wanted.arn, other)],
            invoke,
        )

    def detach_entity_policy_case(self, action, attach_target, detach):
        """
        The shared body of the role and user detach tests, which differ only in
        which entity they act on.

        Four targets carry the policy the grant names, one per key; a fifth
        carries a different policy, so a statement conditioned on the first ARN
        cannot match. The usual non-matching-tag target rounds it out.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        wanted = self.attachable_policy()
        unwanted = self.attachable_policy()

        named = [attach_target(TAG_VALUE, boundary.arn, wanted) for _ in range(4)]
        arn_other = attach_target(TAG_VALUE, boundary.arn, unwanted)
        other = attach_target(OTHER_TAG_VALUE, other_boundary.arn, wanted)

        self.assert_conditions(
            action,
            self.tag_and_boundary_checks(named, boundary.arn)
            + [self.supplied("iam:PolicyARN", wanted.arn, named[3])],
            [
                self.mismatched("iam:PolicyARN", wanted.arn, arn_other),
                self.mismatched_tag(other),
            ],
            detach,
        )

    def test_detach_role_policy(self):
        """
        Test that DetachRolePolicy supplies both resource-tag spellings,
        iam:PermissionsBoundary, and iam:PolicyARN.
        """

        def detach(iam, role):
            log.info(
                "Attempting to detach %s from role %s",
                role.attached_arn,
                role.role_name,
            )
            iam.detach_role_policy(
                RoleName=role.role_name, PolicyArn=role.attached_arn
            )

        self.detach_entity_policy_case(
            "iam:DetachRolePolicy", self.attached_role, detach
        )

    def test_detach_user_policy(self):
        """
        Test that DetachUserPolicy supplies both resource-tag spellings,
        iam:PermissionsBoundary, and iam:PolicyARN.
        """

        def detach(iam, user):
            log.info(
                "Attempting to detach %s from user %s",
                user.attached_arn,
                user.user_name,
            )
            iam.detach_user_policy(
                UserName=user.user_name, PolicyArn=user.attached_arn
            )

        self.detach_entity_policy_case(
            "iam:DetachUserPolicy", self.attached_user, detach
        )
