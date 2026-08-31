#!/usr/bin/env python3
"""
Base case and policy-construction helpers for authorization tests.

These tests differ from everything under tests/api in what they assert: not the
shape of a response, but whether the call was permitted at all. They therefore
run as a created principal rather than as the admin principal.

An end-to-end test can only exercise condition keys a client can influence.
That is a narrower set than the evaluator supports, and the reachable ones are
worth knowing:

    aws:PrincipalTag/<key>  set via the principal's tags -- the main lever
    aws:TagKeys             the multi-valued key, for ForAllValues/ForAnyValue
    aws:username            the principal's user name
    aws:userid              the principal's unique id
    aws:PrincipalArn        the principal's ARN
    aws:CurrentTime         wall clock, for Date* operators
    aws:EpochTime           the same instant, as seconds
    aws:SourceIp            the client address, for IpAddress
    aws:RequestedRegion     the region the call was signed for
    aws:SecureTransport     whether the endpoint is https -- note that a local
                            Scratchstack deployment is http and real AWS is
                            https, so this key differs by target and tests
                            using it must branch rather than assume

Anything outside that list (aws:MultiFactorAuthPresent, service-specific keys,
aws:ResourceTag on IAM resources) needs a unit test against aspen instead.
"""

import json
from typing import Any, Dict, List, Optional, Union

import boto3.session
from botocore.exceptions import ClientError

from .case import IamTestCase, unique_name
from .retry import eventually, eventually_client_error
from .user import User

#: Denials are asserted after the credential has been proven live, so they do
#: not need the full propagation budget. A shorter window keeps a genuinely
#: broken allow from costing thirty seconds per test.
DENY_TIMEOUT = 5.0

#: Error codes that mean "the evaluator said no". IAM uses AccessDenied; some
#: services use AccessDeniedException.
DENIED_CODES = frozenset(("AccessDenied", "AccessDeniedException"))


def statement(
    effect: str,
    *,
    action: Optional[Union[str, List[str]]] = None,
    not_action: Optional[Union[str, List[str]]] = None,
    resource: Optional[Union[str, List[str]]] = None,
    not_resource: Optional[Union[str, List[str]]] = None,
    condition: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Returns an IAM policy statement built from the given parameters.

    Parameters:
        effect: The effect of the statement, either "Allow" or "Deny".
        action: The action or list of actions the statement applies to.
        not_action: The action or list of actions to exclude from the statement.
        resource: The resource or list of resources the statement applies to.
        not_resource: The resource or list of resources to exclude from the statement.
        condition: An optional condition for the statement.

    Exactly one of action or not_action must be specified.
    Exactly one of resource or not_resource must be specified.
    """
    result: Dict[str, Any] = {"Effect": effect}

    if action is None:
        if not_action is None:
            raise ValueError("Exactly one of action or not_action must be specified.")
        result["NotAction"] = not_action
    elif not_action is not None:
        raise ValueError("Exactly one of action or not_action must be specified.")
    else:
        result["Action"] = action

    if resource is None:
        if not_resource is None:
            raise ValueError(
                "Exactly one of resource or not_resource must be specified."
            )
        result["NotResource"] = not_resource
    elif not_resource is not None:
        raise ValueError("Exactly one of resource or not_resource must be specified.")
    else:
        result["Resource"] = resource

    if condition is not None:
        result["Condition"] = condition
    return result


def allow(
    action: Union[str, List[str]],
    resource: Union[str, List[str]] = "*",
    condition: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Returns an IAM policy statement allowing the given action.

    Parameters:
        action: The action or list of actions to allow.
        resource: The resource or list of resources the action applies to.
        condition: An optional condition for the statement.
        **kwargs: Additional keyword arguments passed to the statement function.
    """
    return statement(
        "Allow", action=action, resource=resource, condition=condition, **kwargs
    )


def deny(
    action: Union[str, List[str]],
    resource: Union[str, List[str]] = "*",
    condition: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> Dict[str, Any]:
    return statement(
        "Deny", action=action, resource=resource, condition=condition, **kwargs
    )


def trust_policy(
    principal: str | Dict[str, Any],
    action: str = "sts:AssumeRole",
    condition: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    A role trust policy naming `principal`, which may be an ARN or a dict such
    as {"Service": "ec2.amazonaws.com"}.
    """
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": principal} if isinstance(principal, str) else principal,
        "Action": action,
    }
    if condition is not None:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def policy(*statements: Dict[str, Any]) -> Dict[str, Any]:
    """
    A policy document wrapping the given statements.
    """
    return {"Version": "2012-10-17", "Statement": list(statements)}


class AuthzTestCase(IamTestCase):
    """
    Creates principals and asserts what they may do.

        user = self.subject(permissions=policy(allow("iam:GetUser")))
        iam = user.client("iam")
        self.assertAllowed(lambda: iam.get_user(UserName=user.user_name))
    """

    def subject(self, **kwargs) -> User:
        """
        Create a user, wait for its credential to become usable, and return it.

        sts:GetCallerIdentity requires no permissions, which makes it the one
        call that proves a credential is live without also depending on the
        policy under test. Once it succeeds, propagation is done and later
        assertions -- denials especially -- need no retry budget.
        """
        user = self.fixture(User(self.iam, **kwargs))
        eventually(lambda: user.client("sts").get_caller_identity())
        return user

    @staticmethod
    def json(document) -> str:
        """
        Serialize a policy document for the APIs that take one as a string,
        such as the Policy parameter of AssumeRole.
        """
        return json.dumps(document)

    def target_user(self, **kwargs) -> User:
        """
        Another user, created only to be named -- in a Resource element, or as
        the target of a probe. No credential is waited for, because nothing
        calls as it.
        """
        return self.fixture(User(self.iam, **kwargs))

    def assume(self, user, role, **kwargs) -> boto3.session.Session:
        """
        Assume `role` as `user` and return a boto3 session for the resulting
        credentials.

        A boto3 Session exposes .client() just as the User fixture does, so the
        probes in tests/authz/probes.py accept either.
        """
        sts = user.client("sts")
        kwargs.setdefault("RoleSessionName", unique_name("session-"))
        response = eventually(lambda: sts.assume_role(RoleArn=role.arn, **kwargs))
        credentials = response["Credentials"]
        return boto3.session.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

    def grant_group(self, group, document, *, policy_name=None) -> None:
        """
        Put an inline policy on a group, as the admin principal.
        """
        self.iam.put_group_policy(
            GroupName=group.group_name,
            PolicyName=policy_name or unique_name(),
            PolicyDocument=json.dumps(document),
        )

    def join(self, user, group) -> None:
        """
        Add a user to a group.
        """
        self.iam.add_user_to_group(GroupName=group.group_name, UserName=user.user_name)

    def leave(self, user, group) -> None:
        """
        Remove a user from a group.
        """
        self.iam.remove_user_from_group(
            GroupName=group.group_name, UserName=user.user_name
        )

    def assertAllowed(self, probe, msg=None):
        """
        Verify that the probe is permitted and return its result.

        A non-authorization failure is re-raised rather than reported as a
        denial: a test that misnames a resource should look like a broken test,
        not like a policy that failed to grant.
        """
        try:
            return eventually(probe)
        except ClientError as e:
            error = e.response.get("Error")
            assert isinstance(error, dict)
            code = error.get("Code")
            if code in DENIED_CODES:
                self.fail(
                    f"Expected the call to be allowed, but it was denied. "
                    f"{msg or ''}\n{error.get('Message', '')}"
                )
            raise

    def assertDenied(self, probe, msg=None, *, timeout=DENY_TIMEOUT):
        """
        Verify that the probe is denied and return the raised ClientError.
        """
        try:
            return eventually_client_error("AccessDenied", probe, timeout=timeout)
        except ClientError as e:
            error = e.response.get("Error")
            assert isinstance(error, dict)
            code = error.get("Code")
            self.fail(
                f"Expected AccessDenied, got {code}. {msg or ''}\n"
                f"{error.get('Message', '')}"
            )
