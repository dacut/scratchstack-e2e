#!/usr/bin/env python3
"""
Delete the IAM resources an interrupted test run left behind.

Every fixture in this suite creates its resources under TEST_PATH, and that is
what makes a blind sweep safe: the path is the ownership boundary, so anything
found beneath it belongs to a test run and nothing outside it is touched. A
fixture that created a resource elsewhere would be invisible here and would
accumulate instead.

An IAM principal cannot be deleted while it still holds inline policies,
attached policies, access keys, or group memberships, so each principal is
stripped of those before it is deleted.

Installed as the `scratchstack-e2e-sweep` console script, and runnable in place
as `python -m scratchstack_e2e.sweep`. Pass --prefix to sweep a path other than
TEST_PATH, and --profile or --region to point it at a different account.
"""

import argparse

import boto3
from types_boto3_iam.client import IAMClient

from .case import TEST_PATH
from .retry import eventually


def main():
    parser = argparse.ArgumentParser(
        description="Clean up any straggling IAM resources"
    )
    parser.add_argument("--profile", help="AWS CLI profile to use", default=None)
    parser.add_argument(
        "--region",
        help="AWS region to use",
        default=None,
    )
    parser.add_argument(
        "--prefix",
        help=f"Path prefix for IAM resources to clean up (defaults to {TEST_PATH})",
        default=TEST_PATH,
    )
    args = parser.parse_args()
    prefix = args.prefix
    if not prefix.startswith("/"):
        raise ValueError("Prefix must start with a '/'")
    if not prefix.endswith("/"):
        prefix += "/"

    kw = {}
    if args.region:
        kw["region_name"] = args.region
    if args.profile:
        kw["profile_name"] = args.profile
    session = boto3.Session(**kw)
    iam: IAMClient = session.client("iam")
    cleanup_users(iam, prefix)
    cleanup_roles(iam, prefix)
    cleanup_policies(iam, prefix)
    cleanup_groups(iam, prefix)
    print("Done")


def cleanup_groups(iam: IAMClient, prefix: str) -> None:
    paginator = iam.get_paginator("list_groups")
    groups = []
    for page in eventually(lambda: paginator.paginate(PathPrefix=prefix)):
        groups.extend(page.get("Groups", []))

    for group in groups:
        group_name = group["GroupName"]

        cleanup_group_inline_policies(iam, group_name)
        cleanup_group_attached_policies(iam, group_name)

        print(f"Deleting group: {group_name}")
        eventually(lambda: iam.delete_group(GroupName=group_name))


def cleanup_group_inline_policies(iam: IAMClient, group_name: str) -> None:
    paginator = iam.get_paginator("list_group_policies")
    policies = []
    for page in eventually(lambda: paginator.paginate(GroupName=group_name)):
        policies.extend(page.get("PolicyNames", []))

    for policy_name in policies:
        print(f"Deleting inline policy {policy_name} for group {group_name}")
        eventually(
            lambda: iam.delete_group_policy(
                GroupName=group_name, PolicyName=policy_name
            )
        )


def cleanup_group_attached_policies(iam: IAMClient, group_name: str) -> None:
    paginator = iam.get_paginator("list_attached_group_policies")
    policies = []
    for page in eventually(lambda: paginator.paginate(GroupName=group_name)):
        policies.extend(page.get("AttachedPolicies", []))

    for policy in policies:
        policy_arn = policy["PolicyArn"]
        print(f"Detaching policy {policy_arn} from group {group_name}")
        eventually(
            lambda: iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        )


def cleanup_policies(iam: IAMClient, prefix: str) -> None:
    paginator = iam.get_paginator("list_policies")
    policies = []
    for page in eventually(
        lambda: paginator.paginate(Scope="Local", PathPrefix=prefix)
    ):
        policies.extend(page.get("Policies", []))

    for policy in policies:
        policy_arn = policy["Arn"]
        print(f"Deleting policy: {policy_arn}")
        eventually(lambda: iam.delete_policy(PolicyArn=policy_arn))


def cleanup_roles(iam: IAMClient, prefix: str) -> None:
    paginator = iam.get_paginator("list_roles")
    roles = []
    for page in eventually(lambda: paginator.paginate(PathPrefix=prefix)):
        roles.extend(page.get("Roles", []))

    for role in roles:
        role_name = role["RoleName"]

        cleanup_role_inline_policies(iam, role_name)
        cleanup_role_attached_policies(iam, role_name)

        print(f"Deleting role: {role_name}")
        eventually(lambda: iam.delete_role(RoleName=role_name))


def cleanup_role_inline_policies(iam: IAMClient, role_name: str) -> None:
    paginator = iam.get_paginator("list_role_policies")
    policies = []
    for page in eventually(lambda: paginator.paginate(RoleName=role_name)):
        policies.extend(page.get("PolicyNames", []))

    for policy_name in policies:
        print(f"Deleting inline policy {policy_name} for role {role_name}")
        eventually(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )


def cleanup_role_attached_policies(iam: IAMClient, role_name: str) -> None:
    paginator = iam.get_paginator("list_attached_role_policies")
    policies = []
    for page in eventually(lambda: paginator.paginate(RoleName=role_name)):
        policies.extend(page.get("AttachedPolicies", []))

    for policy in policies:
        policy_arn = policy["PolicyArn"]
        print(f"Detaching policy {policy_arn} from role {role_name}")
        eventually(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )


def cleanup_users(iam: IAMClient, prefix: str) -> None:
    paginator = iam.get_paginator("list_users")
    users = []
    for page in eventually(lambda: paginator.paginate(PathPrefix=prefix)):
        users.extend(page.get("Users", []))

    for user in users:
        user_name = user["UserName"]

        cleanup_user_access_keys(iam, user_name)
        cleanup_user_inline_policies(iam, user_name)
        cleanup_user_attached_policies(iam, user_name)
        remove_user_from_groups(iam, user_name)

        print(f"Deleting user: {user_name}")
        eventually(lambda: iam.delete_user(UserName=user_name))


def cleanup_user_access_keys(iam: IAMClient, user_name: str) -> None:
    paginator = iam.get_paginator("list_access_keys")
    access_keys = []
    for page in eventually(lambda: paginator.paginate(UserName=user_name)):
        access_keys.extend(page.get("AccessKeyMetadata", []))

    for access_key in access_keys:
        access_key_id = access_key["AccessKeyId"]
        print(f"Deleting access key {access_key_id} for user {user_name}")
        eventually(
            lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
        )


def cleanup_user_inline_policies(iam: IAMClient, user_name: str) -> None:
    paginator = iam.get_paginator("list_user_policies")
    policies = []
    for page in eventually(lambda: paginator.paginate(UserName=user_name)):
        policies.extend(page.get("PolicyNames", []))

    for policy_name in policies:
        print(f"Deleting inline policy {policy_name} for user {user_name}")
        eventually(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        )


def cleanup_user_attached_policies(iam: IAMClient, user_name: str) -> None:
    paginator = iam.get_paginator("list_attached_user_policies")
    policies = []
    for page in eventually(lambda: paginator.paginate(UserName=user_name)):
        policies.extend(page.get("AttachedPolicies", []))

    for policy in policies:
        policy_arn = policy["PolicyArn"]
        print(f"Detaching policy {policy_arn} from user {user_name}")
        eventually(
            lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        )


def remove_user_from_groups(iam: IAMClient, user_name: str) -> None:
    paginator = iam.get_paginator("list_groups_for_user")
    groups = []
    for page in eventually(lambda: paginator.paginate(UserName=user_name)):
        groups.extend(page.get("Groups", []))

    for group in groups:
        group_name = group["GroupName"]
        print(f"Removing user {user_name} from group {group_name}")
        eventually(
            lambda: iam.remove_user_from_group(UserName=user_name, GroupName=group_name)
        )


if __name__ == "__main__":
    main()
