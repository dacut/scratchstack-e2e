"""
Tests for user authorization behavior.
"""

from logging import getLogger

from scratchstack_e2e import TEST_PATH, IamTestCase, Policy, User, unique_name
from scratchstack_e2e.arn import Arn
from scratchstack_e2e.aspen import allow, deny, policy
from scratchstack_e2e.retry import eventually, eventually_client_error

log = getLogger(__name__)


class TestUserAuthorization(IamTestCase):
    """
    Tests for user authorization behavior.
    """

    def test_permissions_boundary(self):
        """
        Test that creating a user with a condition iam:PermissionsBoundary in
        the caller's IAM permissions is enforced.
        """
        boundary_permissions = policy(deny(action="*", resource="*"))
        identity = eventually(self.sts.get_caller_identity)
        arn = Arn.parse(identity["Arn"])
        partition = arn.partition
        account_id = arn.account_id
        user_name = unique_name()
        denied_name = unique_name()

        with Policy(self.iam, boundary_permissions) as boundary:
            user_permission = policy(
                allow(
                    action="iam:CreateUser",
                    resource="*",
                    condition={
                        "StringEquals": {"iam:PermissionsBoundary": boundary.arn}
                    },
                ),
                allow(
                    action="iam:DeleteUser",
                    resource=f"arn:{partition}:iam::{account_id}:user{TEST_PATH}{user_name}",
                ),
                # Granted unconditionally as a propagation probe; see below.
                allow(action="iam:ListUsers", resource="*"),
            )
            with User(self.iam, permissions=user_permission) as user:
                iam = user.client("iam")

                # A newly attached inline policy takes time to propagate, and
                # until it does every call is denied for want of any policy at
                # all. iam:ListUsers is granted unconditionally in the same
                # document, so its succeeding rules out that state.
                eventually(lambda: iam.list_users(MaxItems=1))

                # The allowed case runs first, and is retried until the grant
                # is in effect. Only then does a denial mean the condition
                # failed rather than the grant not having arrived: the probe
                # above shows the document is live, but not that this
                # statement's condition is being applied yet.
                def with_pb():
                    log.info(
                        "Attempting to create user %s with permissions boundary",
                        user_name,
                    )
                    iam.create_user(
                        UserName=user_name,
                        Path=TEST_PATH,
                        PermissionsBoundary=boundary.arn,
                    )
                    log.info("Created user %s with permissions boundary", user_name)

                eventually(with_pb)

                # Clean up the created user
                log.info("Deleting user %s", user_name)
                eventually(lambda: iam.delete_user(UserName=user_name))
                log.info("Deleted user %s", user_name)

                # A distinct name, so that the deletion above needing to
                # propagate cannot turn this into EntityAlreadyExists.
                def missing_pb():
                    log.info(
                        "Attempting to create user %s without permissions boundary",
                        denied_name,
                    )
                    iam.create_user(UserName=denied_name, Path=TEST_PATH)
                    log.info("Created user %s", denied_name)

                eventually_client_error("AccessDenied", missing_pb)

    def test_tags(self):
        """
        Test that creating/deleting a user with conditions related to tags in
        the caller's IAM permissions are enforced.
        """
        user_permission = policy(
            allow(
                action=["iam:CreateUser", "iam:TagUser"],
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
                action="iam:DeleteUser",
                resource="*",
                condition={
                    "StringEquals": {
                        "aws:ResourceTag/TestTag1": "TestValue1",
                        "iam:ResourceTag/TestTag1": "TestValue1",
                    },
                },
            ),
            # Granted unconditionally as a propagation probe; see below.
            allow(action="iam:ListUsers", resource="*"),
        )
        with User(self.iam, permissions=user_permission) as user:
            iam = user.client("iam")
            user_name = unique_name()
            denied_name = unique_name()

            # A newly attached inline policy takes time to propagate, and until
            # it does every call is denied for want of any policy at all.
            # iam:ListUsers is granted unconditionally in the same document, so
            # its succeeding rules out that state.
            eventually(lambda: iam.list_users(MaxItems=1))

            # The allowed case runs first, and is retried until the grant is in
            # effect. Only then does a denial mean the condition failed rather
            # than the grant not having arrived: the probe above shows the
            # document is live, but not that this statement's condition is
            # being applied yet.
            def with_tags():
                log.info("Attempting to create user %s with required tags", user_name)
                iam.create_user(
                    UserName=user_name,
                    Path=TEST_PATH,
                    Tags=[{"Key": "TestTag1", "Value": "TestValue1"}],
                )
                log.info("Created user %s with required tags", user_name)

            eventually(with_tags)

            # Clean up the created user
            log.info("Deleting user %s", user_name)
            eventually(lambda: iam.delete_user(UserName=user_name))

            # A distinct name, so that the deletion above needing to propagate
            # cannot turn this into EntityAlreadyExists.
            def missing_tags():
                log.info(
                    "Attempting to create user %s without required tags", denied_name
                )
                iam.create_user(UserName=denied_name, Path=TEST_PATH)
                log.info("Created user %s without required tags", denied_name)

            eventually_client_error("AccessDenied", missing_tags)
