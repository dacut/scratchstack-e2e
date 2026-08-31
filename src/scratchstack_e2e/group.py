#!/usr/bin/env python3
import json
import logging
import secrets

from types_boto3_iam import IAMClient

from .retry import eventually, eventually_or_error

log = logging.getLogger(__name__)


class Group:
    """
    An IAM group that is automatically deleted when used as a context manager.

    The value returned by the context manager is a boto3 session authenticated
    as the newly created IAM group.
    """

    def __init__(
        self,
        iam: IAMClient,
        *,
        group_name=None,
        path="/scratchstack-e2e/",
        permissions=None,
        tags=None,
    ):
        if group_name is None:
            group_name = "scratchstack-test-" + secrets.token_hex(8)
        self.iam = iam
        self.group_name = group_name
        self.path = path
        self.permissions = permissions
        self.tags = tags
        self.credentials = None
        self.arn = None
        self.group_id = None

    def __del__(self):
        self.delete()

    def forget(self):
        """
        Mark the group as already gone, so teardown does not try to delete it.

        For tests whose subject is the deletion itself; see `Role.forget` for
        why the caller rather than the retry helper has to say so.
        """
        self.arn = None
        self.group_id = None

    def delete(self):
        if self.arn is None and self.group_id is None:
            return

        try:
            paginator = self.iam.get_paginator("get_group")
            for page in eventually(
                lambda: paginator.paginate(GroupName=self.group_name)
            ):
                for user in page.get("Users", []):
                    log.info(
                        "Removing user %s from group %s",
                        user["UserName"],
                        self.group_name,
                    )
                    eventually_or_error(
                        lambda: self.iam.remove_user_from_group(
                            GroupName=self.group_name, UserName=user["UserName"]
                        ),
                        allowed=["NoSuchEntity"],
                    )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            paginator = self.iam.get_paginator("list_attached_group_policies")
            for page in eventually(
                lambda: paginator.paginate(GroupName=self.group_name)
            ):
                for policy in page.get("AttachedPolicies", []):
                    policy_arn = policy.get("PolicyArn")
                    if policy_arn is not None:
                        parn = (
                            policy_arn  # Capture local iteration for the lambda/pyright
                        )
                        log.info(
                            "Detaching policy %s from group %s",
                            parn,
                            self.group_name,
                        )
                        eventually_or_error(
                            lambda: self.iam.detach_group_policy(
                                GroupName=self.group_name, PolicyArn=parn
                            ),
                            allowed=["NoSuchEntity"],
                        )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            paginator = self.iam.get_paginator("list_group_policies")
            for page in eventually(
                lambda: paginator.paginate(GroupName=self.group_name)
            ):
                for policy_name in page["PolicyNames"]:
                    log.info(
                        "Deleting inline policy %s from group %s",
                        policy_name,
                        self.group_name,
                    )
                    eventually_or_error(
                        lambda: self.iam.delete_group_policy(
                            GroupName=self.group_name, PolicyName=policy_name
                        ),
                        allowed=["NoSuchEntity"],
                    )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            log.info("Deleting group %s", self.group_name)
            eventually_or_error(
                lambda: self.iam.delete_group(GroupName=self.group_name),
                allowed=["NoSuchEntity"],
            )
        except self.iam.exceptions.NoSuchEntityException:
            pass

    def __enter__(self):
        kw = {}
        if self.tags:
            kw["Tags"] = [{"Key": k, "Value": v} for k, v in self.tags.items()]
        created = eventually(
            lambda: self.iam.create_group(
                GroupName=self.group_name, Path=self.path, **kw
            )
        )["Group"]
        log.info("Created group %s", self.group_name)
        self.arn = created["Arn"]
        self.group_id = created["GroupId"]

        try:
            if self.permissions is not None:
                policy_name = "scratchstack-test-" + secrets.token_hex(8)
                log.info(
                    "Attaching inline policy %s to group %s",
                    policy_name,
                    self.group_name,
                )
                eventually(
                    lambda: self.iam.put_group_policy(
                        GroupName=self.group_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(self.permissions),
                    )
                )
        except:
            self.delete()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.delete()
