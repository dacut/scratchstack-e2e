#!/usr/bin/env python3
import json
import logging
import secrets
from typing import Any, Dict, Optional

import boto3
import boto3.session
from types_boto3_iam import IAMClient

from .case import TEST_PATH, unique_name
from .retry import eventually

log = logging.getLogger(__name__)


class User:
    """
    An IAM user that is automatically deleted when used as a context manager.

    The value returned by the context manager is a boto3 session authenticated
    as the newly created IAM user.
    """

    def __init__(
        self,
        iam: IAMClient,
        *,
        user_name: Optional[str] = None,
        path: str = TEST_PATH,
        permissions: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, str]] = None,
        permissions_boundary: Optional[str] = None,
    ):
        if user_name is None:
            user_name = unique_name()
        self.iam = iam
        self.user_name = user_name
        self.path = path
        self.permissions = permissions
        self.tags = tags
        self.permissions_boundary = permissions_boundary
        self.arn: Optional[str] = None
        self.user_id: Optional[str] = None

    def __del__(self):
        self.delete()

    def delete(self) -> None:
        if self.arn is None and self.user_id is None:
            return

        try:
            paginator = self.iam.get_paginator("list_access_keys")
            for page in eventually(lambda: paginator.paginate(UserName=self.user_name)):
                for key in page.get("AccessKeyMetadata", []):
                    status = key.get("Status")
                    access_key_id = key.get("AccessKeyId")
                    if access_key_id is not None:
                        akid = access_key_id  # Capture local iteration for the lambda/pyright
                        if status == "Active":
                            log.info(
                                "Deactivating access key %s for user %s",
                                akid,
                                self.user_name,
                            )
                            eventually(
                                lambda: self.iam.update_access_key(
                                    UserName=self.user_name,
                                    AccessKeyId=akid,
                                    Status="Inactive",
                                )
                            )

                        log.info(
                            "Deleting access key %s for user %s", akid, self.user_name
                        )
                        eventually(
                            lambda: self.iam.delete_access_key(
                                UserName=self.user_name, AccessKeyId=akid
                            )
                        )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            paginator = self.iam.get_paginator("list_groups_for_user")
            for page in eventually(lambda: paginator.paginate(UserName=self.user_name)):
                for group in page.get("Groups", []):
                    group_name = group.get("GroupName")
                    if group_name is not None:
                        gn = (
                            group_name  # Capture local iteration for the lambda/pyright
                        )
                        log.info("Removing user %s from group %s", self.user_name, gn)
                        eventually(
                            lambda: self.iam.remove_user_from_group(
                                GroupName=gn, UserName=self.user_name
                            )
                        )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            paginator = self.iam.get_paginator("list_attached_user_policies")
            for page in eventually(lambda: paginator.paginate(UserName=self.user_name)):
                for policy in page.get("AttachedPolicies", []):
                    policy_arn = policy.get("PolicyArn")
                    if policy_arn is not None:
                        pa = (
                            policy_arn  # Capture local iteration for the lambda/pyright
                        )
                        log.info(
                            "Detaching user policy %s from user %s", pa, self.user_name
                        )
                        eventually(
                            lambda: self.iam.detach_user_policy(
                                UserName=self.user_name, PolicyArn=pa
                            )
                        )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            paginator = self.iam.get_paginator("list_user_policies")
            for page in eventually(lambda: paginator.paginate(UserName=self.user_name)):
                for policy_name in page.get("PolicyNames", []):
                    if policy_name is not None:
                        pn = policy_name  # Capture local iteration for the lambda/pyright
                        log.info(
                            "Deleting inline user policy %s from user %s",
                            pn,
                            self.user_name,
                        )
                        eventually(
                            lambda: self.iam.delete_user_policy(
                                UserName=self.user_name, PolicyName=pn
                            )
                        )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            log.info("Deleting user %s", self.user_name)
            eventually(lambda: self.iam.delete_user(UserName=self.user_name))
            self.arn = None
            self.user_id = None
            log.info("Deleted user %s", self.user_name)
        except self.iam.exceptions.NoSuchEntityException:
            log.info("User %s does not exist, skipping deletion", self.user_name)
            self.arn = None
            self.user_id = None
            pass
        except Exception as e:
            log.error("Failed to delete user %s: %s", self.user_name, e)
            raise

    def __enter__(self) -> "User":
        kw = {}
        if self.tags:
            kw["Tags"] = [{"Key": k, "Value": v} for k, v in self.tags.items()]
        if self.permissions_boundary:
            kw["PermissionsBoundary"] = self.permissions_boundary

        created = eventually(
            lambda: self.iam.create_user(UserName=self.user_name, Path=self.path, **kw)
        )["User"]
        self.arn = created["Arn"]
        self.user_id = created["UserId"]
        log.info("Created test user %s (%s)", self.user_name, self.user_id)

        try:
            self.credentials = eventually(
                lambda: self.iam.create_access_key(UserName=self.user_name)
            )["AccessKey"]
            log.info(
                "Created access key for test user %s: %s %s",
                self.user_name,
                self.credentials["AccessKeyId"],
                self.credentials["SecretAccessKey"],
            )

            if self.permissions:
                policy_name = "scratchstack-test-" + secrets.token_hex(8)
                log.info(
                    "Attaching inline policy %s to user %s",
                    policy_name,
                    self.user_name,
                )
                eventually(
                    lambda: self.iam.put_user_policy(
                        UserName=self.user_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(self.permissions),
                    )
                )
        except:
            self.delete()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.delete()

    def session(self) -> boto3.session.Session:
        return boto3.session.Session(
            aws_access_key_id=self.credentials["AccessKeyId"],
            aws_secret_access_key=self.credentials["SecretAccessKey"],
        )

    def client(self, service_name, **kwargs):
        return self.session().client(service_name, **kwargs)

    def permission(self, policy_document) -> UserPermission:
        return UserPermission(self.iam, self.user_name, policy_document)


class UserPermission:
    """
    Temporary permission added to a user.
    """

    def __init__(self, iam, user_name, policy_document):
        self.iam = iam
        self.user_name = user_name
        self.policy_document = policy_document
        self.policy_name = "scratchstack-test-" + secrets.token_hex(8)

    def delete(self) -> None:
        try:
            self.iam.delete_user_policy(
                UserName=self.user_name, PolicyName=self.policy_name
            )
        except self.iam.exceptions.NoSuchEntityException:
            pass

    def __enter__(self) -> "UserPermission":
        eventually(
            lambda: self.iam.put_user_policy(
                UserName=self.user_name,
                PolicyName=self.policy_name,
                PolicyDocument=json.dumps(self.policy_document),
            )
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.delete()
