#!/usr/bin/env python3
"""
Base test case shared by every Scratchstack end-to-end test.

Endpoint selection is entirely boto3's job: run the suite with
AWS_PROFILE=scratchstack to exercise a local Scratchstack deployment, or with a
profile naming a real AWS account to vet the suite itself against AWS. Nothing
in this module knows which one it is talking to, and tests must not assume.
"""

import logging
import secrets
import time
import unittest
from contextlib import ExitStack, contextmanager

import boto3.session
from botocore.exceptions import ClientError

from .arn import Arn

#: Path applied to every resource these tests create. The sweeper deletes
#: anything found beneath it, so fixtures must not create resources elsewhere.
TEST_PATH = "/scratchstack-e2e/"

#: Prefix applied to every resource these tests create. It is combined with a
#: random suffix to ensure uniqueness across concurrently running tests.
TEST_PREFIX = "scratchstack-test-"


def unique_name(prefix: str = TEST_PREFIX):
    """
    A resource name that will not collide with a concurrently running test.
    """
    return prefix + secrets.token_hex(8)


class IamTestCase(unittest.TestCase):
    """
    Provides an admin IAM client, scoped fixture cleanup, and assertions for
    the shapes AWS returns.

    Fixtures are entered through `self.fixture`, which unwinds them in reverse
    order at the end of the test whether it passed, failed, or errored:

        user = self.fixture(User(self.iam))
        group = self.fixture(Group(self.iam))
        self.iam.add_user_to_group(...)
    """

    @classmethod
    def setUpClass(cls):
        cls.boto_session = boto3.session.Session()
        cls.iam = cls.boto_session.client("iam")
        cls.sts = cls.boto_session.client("sts")
        cls.account_id = cls.sts.get_caller_identity()["Account"]

    def setUp(self):
        self._fixtures = ExitStack()
        self.addCleanup(self._fixtures.close)

    def fixture(self, context_manager):
        """
        Enter a fixture, registering it for cleanup at the end of the test.
        """
        return self._fixtures.enter_context(context_manager)

    @contextmanager
    def assertClientError(self, code, *, status=None):
        """
        Assert that the body raises a ClientError with the given error code.

        The raised exception is available on the `.exception` attribute of the
        yielded object once the block completes, for tests that need to inspect
        the message.
        """
        with self.assertRaises(ClientError) as raised:
            yield raised

        error = raised.exception.response.get("Error")
        self.assertIsNotNone(error, "Expected 'Error' key in ClientError response")
        assert error is not None  # mypy

        actual_code = error.get("Code")
        self.assertEqual(
            actual_code,
            code,
            f"Expected error code {code!r}, got {actual_code!r}: "
            f"{error.get('Message', '')}",
        )

        if status is not None:
            response_metadata = raised.exception.response.get("ResponseMetadata", {})
            actual_status_code = response_metadata.get("HTTPStatusCode")
            self.assertEqual(
                actual_status_code,
                status,
                f"Expected HTTP status code {status!r}, got {actual_status_code!r}",
            )

    def assertArn(self, arn, *, service, resource_type, name, path=None):
        """
        Assert the structure of an ARN without pinning the partition or region,
        neither of which match between Scratchstack and AWS. The account id is
        checked against the caller's own account.
        """
        parsed = Arn.parse(arn)
        self.assertEqual(parsed.service, service, f"in {arn}")
        self.assertEqual(parsed.resource_type, resource_type, f"in {arn}")
        self.assertEqual(parsed.resource_name, name, f"in {arn}")
        self.assertEqual(parsed.account_id, self.account_id, f"in {arn}")
        if path is not None:
            self.assertEqual(parsed.path, path, f"in {arn}")
        return parsed
