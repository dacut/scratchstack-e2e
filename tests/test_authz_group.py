"""
Tests for group authorization behavior.

CreateGroup has no condition keys, and unlike the other create operations that
is not a documentation gap to go probing at -- it is structural. CreateGroup
takes only Path and GroupName, and IAM has no group-tagging operation at all:
groups are not a taggable resource type, so aws:RequestTag/{}, aws:TagKeys,
aws:ResourceTag/{} and iam:ResourceTag/{} have nothing to be derived from.
There is no iam:PermissionsBoundary either, since a group is not a principal
and carries no boundary.

What remains is the group ARN, and that is worth a test on its own. The ARN is
built from the path and name the request asks for, before any group exists to
read them from, so it is the sole lever a policy has over this operation: a
grant scoped to a path prefix has to reach groups created under that path and
no further. Getting that wrong -- ignoring the requested path when composing
the ARN, say -- would silently widen every path-scoped grant in an account.

The other thing worth pinning is the emptiness of the request context itself.
No IAM API surface can supply a tag key here, but nothing stops *this service*
from supplying one -- pointing CreateGroup at a shared tag-context helper would
do it -- and a key IAM does not define is not harmless: it makes a StringEquals
guard match, and a StringNotEquals deny guard fire, where IAM leaves both
dormant. test_request_context_carries_no_tag_keys is the regression guard for
that, and it is the mirror image of the CreatePolicy case, where the service
turned out to supply a key the documentation omitted.

Deliberately not written here: anything about the global keys every request
carries (aws:PrincipalArn, aws:username, aws:CurrentTime and the rest). Those
are not CreateGroup behavior and the suite exercises them at large.

Ordering follows the rest of the suite: the allowed case first, retried until
the grant is in effect, and only then the denial -- which by that point can
only be the resource scope talking rather than a grant that has not propagated.
"""

from logging import getLogger

from scratchstack_e2e import TEST_PATH, IamTestCase, User, unique_name
from scratchstack_e2e.arn import Arn
from scratchstack_e2e.aspen import allow, policy
from scratchstack_e2e.retry import eventually, eventually_client_error

log = getLogger(__name__)

#: The path the scoped grant below reaches. It sits under TEST_PATH so the
#: sweeper still owns anything left behind.
GRANTED_PATH = f"{TEST_PATH}division/"


class TestGroupAuthorization(IamTestCase):
    """
    Tests for group authorization behavior.
    """

    def test_path_scoped_grant(self):
        """
        Test that CreateGroup is authorized against an ARN built from the path
        and name the request asks for.

        The caller may create groups under GRANTED_PATH and nowhere else. A
        group created there must be allowed, and the identical request at the
        root of the test path -- differing only in the path, so only the ARN
        distinguishes them -- must be denied.
        """
        identity = eventually(self.sts.get_caller_identity)
        arn = Arn.parse(identity["Arn"])
        granted_arn = f"arn:{arn.partition}:iam::{arn.account_id}:group{GRANTED_PATH}*"

        user_permission = policy(
            allow(action="iam:CreateGroup", resource=granted_arn),
            # Deleting is only cleanup here, so its grant carries no scope of
            # its own; iam:ListGroups is the propagation probe.
            allow(action=["iam:DeleteGroup", "iam:ListGroups"], resource="*"),
        )

        with User(self.iam, permissions=user_permission) as user:
            iam = user.client("iam")
            group_name = unique_name()
            denied_name = unique_name()

            # A newly attached inline policy takes time to propagate, and until
            # it does every call is denied for want of any policy at all.
            # iam:ListGroups is granted unconditionally in the same document,
            # so its succeeding rules out that state.
            eventually(lambda: iam.list_groups(MaxItems=1))

            # The allowed case runs first, and is retried until the grant is in
            # effect. Only then does a denial mean the ARN fell outside the
            # grant rather than the grant not having arrived.
            def inside_the_grant():
                log.info(
                    "Attempting to create group %s under %s", group_name, GRANTED_PATH
                )
                iam.create_group(GroupName=group_name, Path=GRANTED_PATH)
                log.info("Created group %s", group_name)

            eventually(inside_the_grant)

            log.info("Deleting group %s", group_name)
            eventually(lambda: iam.delete_group(GroupName=group_name))

            # The same request one path component up. The grant names a prefix,
            # so this ARN is outside it.
            def outside_the_grant():
                log.info(
                    "Attempting to create group %s under %s", denied_name, TEST_PATH
                )
                iam.create_group(GroupName=denied_name, Path=TEST_PATH)
                log.info("Created group %s", denied_name)

            eventually_client_error("AccessDenied", outside_the_grant)

    def test_request_context_carries_no_tag_keys(self):
        """
        Test that CreateGroup's request context carries no tag condition keys.

        Groups are not a taggable resource in IAM -- CreateGroup takes no Tags,
        and there is no TagGroup at all -- so aws:RequestTag/{} must never be
        present. This asserts that from both sides, against three group names
        whose statements differ only in the condition attached to them:

        * no condition, which proves the grant is live and CreateGroup works;
        * `Null: {"aws:RequestTag/foo": "true"}`, which matches only when the
          key is absent, and so must be allowed;
        * `StringEquals: {"aws:RequestTag/foo": "anything"}`, which cannot match
          an absent key, and so must be denied.

        The Null half is the load-bearing one. StringEquals failing is
        ambiguous -- it fails for an absent key and for a key holding some other
        value alike -- so on its own it would not catch the service supplying
        aws:RequestTag/foo as, say, an empty string. Null tests presence
        directly, and the pair together pin the key as genuinely absent rather
        than merely not equal to what was asked.
        """
        identity = eventually(self.sts.get_caller_identity)
        arn = Arn.parse(identity["Arn"])

        control_name = unique_name()
        absent_name = unique_name()
        present_name = unique_name()

        def group_arn(name):
            return f"arn:{arn.partition}:iam::{arn.account_id}:group{TEST_PATH}{name}"

        user_permission = policy(
            # The control: same action, same path, no condition at all.
            allow(action="iam:CreateGroup", resource=group_arn(control_name)),
            allow(
                action="iam:CreateGroup",
                resource=group_arn(absent_name),
                condition={"Null": {"aws:RequestTag/foo": "true"}},
            ),
            allow(
                action="iam:CreateGroup",
                resource=group_arn(present_name),
                condition={"StringEquals": {"aws:RequestTag/foo": "anything"}},
            ),
            allow(action=["iam:DeleteGroup", "iam:ListGroups"], resource="*"),
        )

        with User(self.iam, permissions=user_permission) as user:
            iam = user.client("iam")
            eventually(lambda: iam.list_groups(MaxItems=1))

            def create(name):
                log.info("Attempting to create group %s", name)
                iam.create_group(GroupName=name, Path=TEST_PATH)
                log.info("Created group %s", name)

            # Unconditioned: proves the grant is in effect before anything is
            # read into a denial.
            eventually(lambda: create(control_name))
            eventually(lambda: iam.delete_group(GroupName=control_name))

            # Allowed only while aws:RequestTag/foo is absent.
            eventually(lambda: create(absent_name))
            eventually(lambda: iam.delete_group(GroupName=absent_name))

            # No value can match a key that is not there.
            eventually_client_error(
                "AccessDenied", lambda: create(present_name)
            )
