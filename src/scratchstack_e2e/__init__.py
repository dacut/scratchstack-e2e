#!/usr/bin/env python3
# NOTE: the module holding ManagedPolicy is named managed_policy, not policy.
# A submodule named `policy` would be bound as an attribute of this package on
# import and silently shadow the policy() helper re-exported from .authz.
from .arn import Arn
from .aspen import AuthzTestCase, allow, deny, policy, statement, trust_policy
from .case import TEST_PATH, IamTestCase, unique_name
from .group import Group
from .policy import Policy
from .role import Role
from .user import User

__all__ = [
    "TEST_PATH",
    "Arn",
    "AuthzTestCase",
    "Group",
    "IamTestCase",
    "Policy",
    "Role",
    "User",
    "allow",
    "deny",
    "policy",
    "statement",
    "trust_policy",
    "unique_name",
]
