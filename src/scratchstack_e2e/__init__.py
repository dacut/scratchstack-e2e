#!/usr/bin/env python3
# NOTE: the module holding the Policy fixture is named managed_policy, not
# policy, and must stay that way. Importing a submodule binds it as an
# attribute of its package, so a module named `policy` shadows the policy()
# helper re-exported from .aspen below whenever the submodule is imported
# second -- which is exactly the order isort produces, `.aspen` sorting before
# `.policy`. Reordering the two lines does fix it, but the next formatter run
# silently undoes that; a distinct module name removes the collision instead.
#
# The failure is quiet: `from scratchstack_e2e import policy` still binds a
# name, imports cleanly, and collects cleanly. It raises "'module' object is
# not callable" only where it is called. tests/test_package_exports.py guards
# the general case.
from .arn import Arn
from .aspen import AuthzTestCase, allow, deny, policy, statement, trust_policy
from .case import TEST_PATH, IamTestCase, unique_name
from .group import Group
from .managed_policy import Policy
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
