#!/usr/bin/env python3
"""
IAM role fixture, for tests that assume a role rather than call as a user.
"""

import json
from typing import Any, Dict, Optional

from types_boto3_iam import IAMClient

from .case import TEST_PATH, unique_name
from .retry import eventually


class Role:
    """
    An IAM role that is deleted when the context manager exits.

    `trust_policy` is required and has no default: a role whose trust policy
    were guessed would quietly change what every assume-role test means.
    """

    def __init__(
        self,
        iam: IAMClient,
        trust_policy: Dict[str, Any],
        *,
        role_name: Optional[str] = None,
        path: str = TEST_PATH,
        permissions: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, str]] = None,
        max_session_duration: Optional[int] = None,
        permissions_boundary: Optional[str] = None,
    ):
        if role_name is None:
            role_name = unique_name()
        self.arn: Optional[str] = None
        self.iam = iam
        self.max_session_duration = max_session_duration
        self.path = path
        self.permissions = permissions
        self.permissions_boundary = permissions_boundary
        self.role_name = role_name
        self.tags = tags
        self.trust_policy = trust_policy

    def delete(self):
        try:
            paginator = self.iam.get_paginator("list_attached_role_policies")
            for page in eventually(lambda: paginator.paginate(RoleName=self.role_name)):
                for policy in page.get("AttachedPolicies", []):
                    policy_arn = policy.get("PolicyArn")
                    if policy_arn is not None:
                        parn = (
                            policy_arn  # Capture local iteration for the lambda/pyright
                        )
                        eventually(
                            lambda: self.iam.detach_role_policy(
                                RoleName=self.role_name, PolicyArn=parn
                            )
                        )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            paginator = self.iam.get_paginator("list_role_policies")
            for page in eventually(lambda: paginator.paginate(RoleName=self.role_name)):
                for policy_name in page["PolicyNames"]:
                    eventually(
                        lambda: self.iam.delete_role_policy(
                            RoleName=self.role_name, PolicyName=policy_name
                        )
                    )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            eventually(lambda: self.iam.delete_role(RoleName=self.role_name))
        except self.iam.exceptions.NoSuchEntityException:
            pass

    def __enter__(self):
        kw = {}
        if self.tags:
            kw["Tags"] = [{"Key": k, "Value": v} for k, v in self.tags.items()]
        if self.max_session_duration is not None:
            kw["MaxSessionDuration"] = self.max_session_duration
        if self.permissions_boundary is not None:
            kw["PermissionsBoundary"] = self.permissions_boundary

        response = eventually(
            lambda: self.iam.create_role(
                RoleName=self.role_name,
                Path=self.path,
                AssumeRolePolicyDocument=json.dumps(self.trust_policy),
                **kw,
            )
        )
        self.arn = response["Role"]["Arn"]

        try:
            if self.permissions:
                eventually(
                    lambda: self.iam.put_role_policy(
                        RoleName=self.role_name,
                        PolicyName=unique_name(),
                        PolicyDocument=json.dumps(self.permissions),
                    )
                )
        except:
            self.delete()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.delete()
