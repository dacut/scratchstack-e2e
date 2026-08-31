#!/usr/bin/env python3
"""
Customer-managed policy fixture.

Needed by any test that exercises a policy *by ARN* rather than inline:
attached policies, and permissions boundaries, which accept only a managed
policy ARN.
"""

import json
import logging
from typing import Any, Dict, Optional

from types_boto3_iam import IAMClient

from .case import TEST_PATH, unique_name
from .retry import eventually, eventually_or_error

log = logging.getLogger(__name__)


class Policy:
    """
    A managed policy that is deleted when the context manager exits.

    The ARN is available as `.arn` once entered.

    `tags` are applied by the creating call rather than by a TagPolicy
    afterwards, so a test conditioned on the policy's tags has nothing extra to
    wait out: the policy is never visible untagged.
    """

    def __init__(
        self,
        iam: IAMClient,
        document: Dict[str, Any],
        *,
        policy_name: Optional[str] = None,
        path: str = TEST_PATH,
        description: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ):
        if policy_name is None:
            policy_name = unique_name()
        self.arn: Optional[str] = None
        self.description = description
        self.document = document
        self.iam = iam
        self.path = path
        self.policy_name = policy_name
        self.tags = tags

    def forget(self):
        """
        Mark the policy as already gone, so teardown does not try to delete it.

        For tests whose subject is the deletion itself; see `Role.forget` for
        why the caller rather than the retry helper has to say so.
        """
        self.arn = None

    def delete(self):
        arn = self.arn
        if arn is None:
            return

        # A policy cannot be deleted while attached, and its non-default
        # versions have to go before the policy itself.
        detachers = {
            "PolicyUsers": ("UserName", "detach_user_policy"),
            "PolicyGroups": ("GroupName", "detach_group_policy"),
            "PolicyRoles": ("RoleName", "detach_role_policy"),
        }
        try:
            paginator = self.iam.get_paginator("list_entities_for_policy")
            for page in eventually(lambda: paginator.paginate(PolicyArn=arn)):
                for key, (name_field, method) in detachers.items():
                    for entity in page.get(key, []):
                        log.info(
                            "Detaching policy %s from %s %s",
                            arn,
                            key[:-1],  # remove the plural 's' from the key
                            entity[name_field],
                        )
                        kwargs = {name_field: entity[name_field], "PolicyArn": arn}
                        eventually_or_error(
                            lambda: getattr(self.iam, method)(**kwargs),
                            allowed=["NoSuchEntity"],
                        )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            paginator = self.iam.get_paginator("list_policy_versions")
            for page in eventually(lambda: paginator.paginate(PolicyArn=arn)):
                for version in page["Versions"]:
                    if not version.get("IsDefaultVersion"):
                        version_id = version.get("VersionId")
                        if version_id is not None:
                            vid = version_id  # capture the current version_id for the lambda closure
                            log.info(
                                "Deleting non-default policy version %s for policy %s",
                                vid,
                                arn,
                            )
                            eventually_or_error(
                                lambda: self.iam.delete_policy_version(
                                    PolicyArn=arn, VersionId=vid
                                ),
                                allowed=["NoSuchEntity"],
                            )
        except self.iam.exceptions.NoSuchEntityException:
            pass

        try:
            log.info("Deleting policy %s", arn)
            eventually_or_error(
                lambda: self.iam.delete_policy(PolicyArn=arn),
                allowed=["NoSuchEntity"],
            )
        except self.iam.exceptions.NoSuchEntityException:
            pass

    def __enter__(self):
        kw = {}
        if self.description is not None:
            kw["Description"] = self.description
        if self.tags:
            kw["Tags"] = [{"Key": k, "Value": v} for k, v in self.tags.items()]

        log.info("Creating policy %s", self.policy_name)
        response = eventually(
            lambda: self.iam.create_policy(
                PolicyName=self.policy_name,
                Path=self.path,
                PolicyDocument=json.dumps(self.document),
                **kw,
            )
        )
        self.arn = response.get("Policy", {}).get("Arn")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.delete()
