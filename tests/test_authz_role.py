"""
Tests for role authorization behavior.

These mirror tests/test_authz_user.py case for case: CreateRole builds the same
request context CreateUser does, populating aws:RequestTag/{}, aws:TagKeys,
aws:ResourceTag/{}, iam:ResourceTag/{}, and iam:PermissionsBoundary, so the
grants that gate creating a user gate creating a role in the same way.

The one structural difference is the trust policy. CreateRole requires an
AssumeRolePolicyDocument, so each test builds one naming the caller's own
account root -- a principal that is always valid and grants nothing on its
own, since nothing here assumes the role.
"""

from json import dumps
from logging import getLogger

from scratchstack_e2e import TEST_PATH, IamTestCase, Policy, User, unique_name
from scratchstack_e2e.arn import Arn
from scratchstack_e2e.aspen import allow, deny, policy, trust_policy
from scratchstack_e2e.retry import eventually, eventually_client_error

log = getLogger(__name__)


class TestRoleAuthorization(IamTestCase):
    """
    Tests for role authorization behavior.
    """

    def account_root(self) -> Arn:
        """
        The caller's own identity, parsed, for the partition and account id
        that the trust policy and resource ARNs are built from. Neither can be
        hardcoded: the partition is "local" against Scratchstack and "aws"
        against real AWS.
        """
        identity = eventually(self.sts.get_caller_identity)
        return Arn.parse(identity["Arn"])

    def test_permissions_boundary(self):
        """
        Test that creating a role with a condition iam:PermissionsBoundary in
        the caller's IAM permissions is enforced.
        """
        boundary_permissions = policy(deny(action="*", resource="*"))
        arn = self.account_root()
        partition = arn.partition
        account_id = arn.account_id
        role_name = unique_name()
        denied_name = unique_name()

        # The role is never assumed, so the trust policy only has to be a
        # valid one. Naming the account root grants nothing by itself.
        assume_role_policy = dumps(
            trust_policy(f"arn:{partition}:iam::{account_id}:root")
        )

        with Policy(self.iam, boundary_permissions) as boundary:
            user_permission = policy(
                allow(
                    action="iam:CreateRole",
                    resource="*",
                    condition={
                        "StringEquals": {"iam:PermissionsBoundary": boundary.arn}
                    },
                ),
                allow(
                    action="iam:DeleteRole",
                    resource=f"arn:{partition}:iam::{account_id}:role{TEST_PATH}{role_name}",
                ),
                # Granted unconditionally as a propagation probe; see below.
                allow(action="iam:ListRoles", resource="*"),
            )
            with User(self.iam, permissions=user_permission) as user:
                iam = user.client("iam")

                # A newly attached inline policy takes time to propagate, and
                # until it does every call is denied for want of any policy at
                # all. iam:ListRoles is granted unconditionally in the same
                # document, so its succeeding rules out that state.
                eventually(lambda: iam.list_roles(MaxItems=1))

                # The allowed case runs first, and is retried until the grant
                # is in effect. Only then does a denial mean the condition
                # failed rather than the grant not having arrived: the probe
                # above shows the document is live, but not that this
                # statement's condition is being applied yet.
                def with_pb():
                    log.info(
                        "Attempting to create role %s with permissions boundary",
                        role_name,
                    )
                    iam.create_role(
                        RoleName=role_name,
                        Path=TEST_PATH,
                        AssumeRolePolicyDocument=assume_role_policy,
                        PermissionsBoundary=boundary.arn,
                    )
                    log.info("Created role %s with permissions boundary", role_name)

                eventually(with_pb)

                # Clean up the created role
                log.info("Deleting role %s", role_name)
                eventually(lambda: iam.delete_role(RoleName=role_name))
                log.info("Deleted role %s", role_name)

                # A distinct name, so that the deletion above needing to
                # propagate cannot turn this into EntityAlreadyExists.
                def missing_pb():
                    log.info(
                        "Attempting to create role %s without permissions boundary",
                        denied_name,
                    )
                    iam.create_role(
                        RoleName=denied_name,
                        Path=TEST_PATH,
                        AssumeRolePolicyDocument=assume_role_policy,
                    )
                    log.info("Created role %s", denied_name)

                eventually_client_error("AccessDenied", missing_pb)

    def test_tags(self):
        """
        Test that creating/deleting a role with conditions related to tags in
        the caller's IAM permissions are enforced.

        The grant names aws:ResourceTag and iam:ResourceTag alongside
        aws:RequestTag, which CreateRole populates from the tags the request
        asks for even though the role does not exist yet. A service that
        supplied only the request-tag keys would leave this grant unsatisfied
        and deny the create.
        """
        arn = self.account_root()
        assume_role_policy = dumps(
            trust_policy(f"arn:{arn.partition}:iam::{arn.account_id}:root")
        )

        user_permission = policy(
            allow(
                action=["iam:CreateRole", "iam:TagRole"],
                resource="*",
                condition={
                    "StringEquals": {
                        "aws:ResourceTag/TestTag1": "TestValue1",
                        "aws:RequestTag/TestTag1": "TestValue1",
                        "iam:ResourceTag/TestTag1": "TestValue1",
                    },
                    "ForAnyValue:StringEquals": {
                        "aws:TagKeys": "TestTag1",
                    },
                },
            ),
            allow(
                action="iam:DeleteRole",
                resource="*",
                condition={
                    "StringEquals": {
                        "aws:ResourceTag/TestTag1": "TestValue1",
                        "iam:ResourceTag/TestTag1": "TestValue1",
                    },
                },
            ),
            # Granted unconditionally as a propagation probe; see below.
            allow(action="iam:ListRoles", resource="*"),
        )
        with User(self.iam, permissions=user_permission) as user:
            iam = user.client("iam")
            role_name = unique_name()
            denied_name = unique_name()

            # A newly attached inline policy takes time to propagate, and until
            # it does every call is denied for want of any policy at all.
            # iam:ListRoles is granted unconditionally in the same document, so
            # its succeeding rules out that state.
            eventually(lambda: iam.list_roles(MaxItems=1))

            # The allowed case runs first, and is retried until the grant is in
            # effect. Only then does a denial mean the condition failed rather
            # than the grant not having arrived: the probe above shows the
            # document is live, but not that this statement's condition is
            # being applied yet.
            def with_tags():
                log.info("Attempting to create role %s with required tags", role_name)
                iam.create_role(
                    RoleName=role_name,
                    Path=TEST_PATH,
                    AssumeRolePolicyDocument=assume_role_policy,
                    Tags=[{"Key": "TestTag1", "Value": "TestValue1"}],
                )
                log.info("Created role %s with required tags", role_name)

            eventually(with_tags)

            # Clean up the created role
            log.info("Deleting role %s", role_name)
            eventually(lambda: iam.delete_role(RoleName=role_name))

            # A distinct name, so that the deletion above needing to propagate
            # cannot turn this into EntityAlreadyExists.
            def missing_tags():
                log.info(
                    "Attempting to create role %s without required tags", denied_name
                )
                iam.create_role(
                    RoleName=denied_name,
                    Path=TEST_PATH,
                    AssumeRolePolicyDocument=assume_role_policy,
                )
                log.info("Created role %s without required tags", denied_name)

            eventually_client_error("AccessDenied", missing_tags)
