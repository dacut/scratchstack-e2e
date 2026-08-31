"""
Tests for the condition keys the read operations supply.

Reading an entity is authorized against that entity, and the keys describing it
come from the entity rather than from the request. Nothing here mutates its
target, so a single subject principal and one set of targets cover many
operations at once -- which is why these are grouped by resource type rather
than one test per action.

    GetPolicy, GetPolicyVersion,
      ListPolicyTags, ListPolicyVersions            tags
    GetRolePolicy, ListAttachedRolePolicies,
      ListRolePolicies, ListRoleTags                tags
    GetUser, GetUserPolicy, ListAttachedUserPolicies,
      ListUserPolicies, ListUserTags                tags
    GetRole                                         tags + boundary
    GetGroup, GetGroupPolicy                        nothing
    ListGroups, ListPolicies, ListRoles, ListUsers  no resource, no extra keys

GetRole and GetUser are asymmetric in the documentation, exactly as DeleteRole
and DeleteUser are: the role form carries iam:PermissionsBoundary and the user
form does not. Both halves are asserted, and every target in the GetUser test
carries a boundary -- against a user with none the key would be missing for
want of a value rather than because the operation withholds it, and the test
would pass without having looked at the question.

The account-wide list operations are asserted to supply no keys *beyond* what
the request itself implies: aws:ResourceAccount is left alone, being derived
from the caller rather than from anything the operation names.

Absences are asserted from both sides throughout: Null matches only a key that
is missing and must be allowed, StringEquals cannot match one and must be
denied. Neither half suffices alone.
"""

from logging import getLogger

from scratchstack_e2e import User
from scratchstack_e2e.aspen import allow, policy
from scratchstack_e2e.conditions import (
    INLINE_POLICY_NAME,
    OTHER_TAG_VALUE,
    TAG_KEY,
    TAG_VALUE,
    Check,
    ConditionTestCase,
    eventually_not_denied,
)
from scratchstack_e2e.retry import eventually, eventually_client_error

log = getLogger(__name__)

#: The resource-tag key the absence assertions are written against. Any key the
#: operation does not supply would do; this one is the plausible mistake.
TAG_CONDITION_KEY = f"aws:ResourceTag/{TAG_KEY}"


class TestReadConditions(ConditionTestCase):
    """
    Tests for the condition keys the read operations supply.
    """

    def policy_targets(self, **kwargs):
        named = [self.target_policy(TAG_VALUE, **kwargs) for _ in range(2)]
        return named, self.target_policy(OTHER_TAG_VALUE, **kwargs)

    def role_targets(self, boundary_arn=None, count=2):
        named = [
            self.target_role(TAG_VALUE, boundary_arn, with_inline_policy=True)
            for _ in range(count)
        ]
        return named, self.target_role(
            OTHER_TAG_VALUE, boundary_arn, with_inline_policy=True
        )

    def user_targets(self, boundary_arn=None, count=2):
        named = [
            self.target_user(TAG_VALUE, boundary_arn, with_inline_policy=True)
            for _ in range(count)
        ]
        return named, self.target_user(
            OTHER_TAG_VALUE, boundary_arn, with_inline_policy=True
        )

    def test_policy_reads_supply_resource_tags(self):
        """
        Test that the managed policy read operations supply both resource-tag
        spellings from the policy being read.
        """
        named, other = self.policy_targets()

        operations = [
            ("iam:GetPolicy", lambda iam, p: iam.get_policy(PolicyArn=p.arn)),
            (
                "iam:GetPolicyVersion",
                lambda iam, p: iam.get_policy_version(PolicyArn=p.arn, VersionId="v1"),
            ),
            (
                "iam:ListPolicyTags",
                lambda iam, p: iam.list_policy_tags(PolicyArn=p.arn),
            ),
            (
                "iam:ListPolicyVersions",
                lambda iam, p: iam.list_policy_versions(PolicyArn=p.arn),
            ),
        ]
        self.assert_operations(
            operations, self.tag_checks(named), [self.mismatched_tag(other)]
        )

    @staticmethod
    def role_read_operations():
        """The role reads documented to carry the resource tags alone."""
        return [
            (
                "iam:GetRolePolicy",
                lambda iam, r: iam.get_role_policy(
                    RoleName=r.role_name, PolicyName=INLINE_POLICY_NAME
                ),
            ),
            (
                "iam:ListAttachedRolePolicies",
                lambda iam, r: iam.list_attached_role_policies(RoleName=r.role_name),
            ),
            (
                "iam:ListRolePolicies",
                lambda iam, r: iam.list_role_policies(RoleName=r.role_name),
            ),
            (
                "iam:ListRoleTags",
                lambda iam, r: iam.list_role_tags(RoleName=r.role_name),
            ),
        ]

    @staticmethod
    def user_read_operations():
        """The user reads, all documented to carry the resource tags alone."""
        return [
            ("iam:GetUser", lambda iam, u: iam.get_user(UserName=u.user_name)),
            (
                "iam:GetUserPolicy",
                lambda iam, u: iam.get_user_policy(
                    UserName=u.user_name, PolicyName=INLINE_POLICY_NAME
                ),
            ),
            (
                "iam:ListAttachedUserPolicies",
                lambda iam, u: iam.list_attached_user_policies(UserName=u.user_name),
            ),
            (
                "iam:ListUserPolicies",
                lambda iam, u: iam.list_user_policies(UserName=u.user_name),
            ),
            (
                "iam:ListUserTags",
                lambda iam, u: iam.list_user_tags(UserName=u.user_name),
            ),
        ]

    def test_role_reads_supply_resource_tags(self):
        """
        Test that the role read operations supply both resource-tag spellings.
        """
        named, other = self.role_targets()

        self.assert_operations(
            self.role_read_operations(),
            self.tag_checks(named),
            [self.mismatched_tag(other)],
        )

    def test_role_reads_withhold_the_permissions_boundary(self):
        """
        Test that the role read operations other than GetRole do not supply
        iam:PermissionsBoundary.

        Both targets carry a boundary, which is what makes this mean anything:
        against a role with none the key would be missing for want of a value
        rather than because the operation withholds it. The two halves need
        separate targets -- a Null statement and a StringEquals statement over
        the same role would both apply to the same call, and the allow would
        satisfy the request the denial was meant to refuse.
        """
        boundary = self.boundary_policy()
        absent_target = self.target_role(
            TAG_VALUE, boundary.arn, with_inline_policy=True
        )
        compared_target = self.target_role(
            TAG_VALUE, boundary.arn, with_inline_policy=True
        )

        self.assert_operations(
            self.role_read_operations(),
            [self.absent("iam:PermissionsBoundary", absent_target)],
            [self.mismatched("iam:PermissionsBoundary", boundary.arn, compared_target)],
        )

    def test_user_reads_supply_resource_tags(self):
        """
        Test that the user read operations supply both resource-tag spellings.
        """
        named, other = self.user_targets()

        self.assert_operations(
            self.user_read_operations(),
            self.tag_checks(named),
            [self.mismatched_tag(other)],
        )

    def test_user_reads_withhold_the_permissions_boundary(self):
        """
        Test that the user read operations do not supply
        iam:PermissionsBoundary.

        This is the other half of the GetRole/GetUser asymmetry: the
        documentation gives the role form the boundary key and withholds it
        from the user form, exactly as DeleteRole and DeleteUser differ. Both
        targets carry a boundary, so an absence here means the operation
        withholds the key rather than there being no value to report.
        """
        boundary = self.boundary_policy()
        absent_target = self.target_user(
            TAG_VALUE, boundary.arn, with_inline_policy=True
        )
        compared_target = self.target_user(
            TAG_VALUE, boundary.arn, with_inline_policy=True
        )

        self.assert_operations(
            self.user_read_operations(),
            [self.absent("iam:PermissionsBoundary", absent_target)],
            [self.mismatched("iam:PermissionsBoundary", boundary.arn, compared_target)],
        )

    def test_get_role_supplies_the_permissions_boundary(self):
        """
        Test that GetRole supplies both resource-tag spellings and
        iam:PermissionsBoundary.

        This is the other half of the asymmetry: the same key the user read
        operations withhold, the role form carries.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [self.target_role(TAG_VALUE, boundary.arn) for _ in range(3)]
        other = self.target_role(OTHER_TAG_VALUE, other_boundary.arn)

        self.assert_conditions(
            "iam:GetRole",
            self.tag_and_boundary_checks(named, boundary.arn),
            [self.mismatched_tag(other)],
            lambda iam, r: iam.get_role(RoleName=r.role_name),
        )

    def test_group_reads_supply_no_context(self):
        """
        Test that GetGroup and GetGroupPolicy supply no request context.

        Groups are neither taggable nor principals, so there is nothing for a
        condition key to describe.
        """
        unconditioned = self.target_group(with_inline_policy=True)
        null_checked = self.target_group(with_inline_policy=True)
        other = self.target_group(with_inline_policy=True)

        operations = [
            ("iam:GetGroup", lambda iam, g: iam.get_group(GroupName=g.group_name)),
            (
                "iam:GetGroupPolicy",
                lambda iam, g: iam.get_group_policy(
                    GroupName=g.group_name, PolicyName=INLINE_POLICY_NAME
                ),
            ),
        ]
        self.assert_operations(
            operations,
            [
                Check("no condition at all", None, unconditioned),
                self.absent(TAG_CONDITION_KEY, null_checked),
            ],
            [self.mismatched(TAG_CONDITION_KEY, TAG_VALUE, other)],
        )

    def test_account_list_reads_take_no_resource_and_no_context(self):
        """
        Test that ListGroups, ListPolicies, ListRoles and ListUsers are
        authorized against no resource and supply no request context.

        These cannot share one grant the way the others do. With no resource to
        scope statements by, an allow anywhere in the document would permit the
        call, so allow and deny cannot sit side by side -- each case needs its
        own subject. The probe is iam:GetUser on a target, an action not under
        test here, so that a denial of the list operations still means the
        document is live.

        Four cases, in order: granted on "*" it works; a grant that applies
        only while a resource tag is absent works, so no such key is supplied;
        a grant requiring that key to equal something cannot match; and a grant
        scoped to an entity ARN does not reach an operation that names no
        resource.
        """
        probe_target = self.target_user(TAG_VALUE)
        calls = [
            ("iam:ListGroups", lambda iam: iam.list_groups(MaxItems=1)),
            ("iam:ListPolicies", lambda iam: iam.list_policies(MaxItems=1)),
            ("iam:ListRoles", lambda iam: iam.list_roles(MaxItems=1)),
            ("iam:ListUsers", lambda iam: iam.list_users(MaxItems=1)),
        ]
        actions = [action for action, _call in calls]

        def run(label, resource, condition, expect_allowed):
            arn = probe_target.arn
            assert arn is not None
            grant = policy(
                allow(action=actions, resource=resource, condition=condition),
                # Not one of the operations under test, so it stays available
                # even in the cases where those must be refused.
                allow(action="iam:GetUser", resource=arn),
            )
            with User(self.iam, permissions=grant) as subject:
                iam = subject.client("iam")
                eventually(lambda: iam.get_user(UserName=probe_target.user_name))

                for action, call in calls:
                    with self.subTest(case=label, action=action):
                        log.info(
                            "%s: expecting %s to be %s",
                            label,
                            action,
                            "allowed" if expect_allowed else "denied",
                        )
                        if expect_allowed:
                            eventually_not_denied(lambda: call(iam))
                        else:
                            eventually_client_error("AccessDenied", lambda: call(iam))

        run("granted on *", "*", None, True)
        run(
            "resource tag absent",
            "*",
            {"Null": {TAG_CONDITION_KEY: "true"}},
            True,
        )
        run(
            "resource tag compared",
            "*",
            {"StringEquals": {TAG_CONDITION_KEY: TAG_VALUE}},
            False,
        )
        run("scoped to an entity ARN", probe_target.arn, None, False)
