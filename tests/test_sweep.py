"""
Tests for the order in which the sweeper deletes things.

These need no AWS credentials: boto3 and the four sweep phases are stubbed, and
what is asserted is the sequence main() calls them in.

That sequence is a correctness constraint rather than a preference, and it is
one nothing else can check. IAM refuses to delete a managed policy while
anything is still attached to it, and refuses to delete a group that still has
members; each phase clears its own principals' attachments as it goes, so a
phase running out of turn leaves a reference standing and the delete comes back
DeleteConflict. `eventually` then retries that for its full budget before
raising, which aborts the sweep partway -- the resources the later phases would
have removed stay behind, and the next run trips over the same conflict.

The bug this guards against was live: policies were swept before groups, so a
managed policy attached to a group could never be deleted. Nothing in the suite
noticed, because the failure needs both a real account and an interrupted run
that had attached a managed policy to a group -- which
tests/test_authz_existing_entity.py does.
"""

import sys
from unittest import TestCase
from unittest.mock import patch

from scratchstack_e2e import sweep

#: The sweep phases, in the order main() must call them.
PHASES = ("users", "roles", "groups", "policies")


class TestSweepOrder(TestCase):
    """
    Tests for the order in which the sweeper deletes things.
    """

    @staticmethod
    def run_main(*argv):
        """
        Run sweep.main() with boto3 and every phase stubbed, returning the
        phase names in the order they were called.
        """
        calls = []

        def record(name):
            def phase(iam, prefix):
                calls.append(name)

            return phase

        patches = [
            patch.object(sweep, "boto3"),
            patch.object(sys, "argv", ["sweep", *argv]),
        ]
        patches += [
            patch.object(sweep, f"cleanup_{name}", record(name)) for name in PHASES
        ]

        for entered in patches:
            entered.start()
        try:
            sweep.main()
        finally:
            for entered in reversed(patches):
                entered.stop()

        return calls

    def test_every_phase_runs(self):
        """
        Test that main() calls all four phases, once each.

        Asserted separately so that an ordering failure below is an ordering
        failure and not a phase that silently stopped being called.
        """
        self.assertEqual(sorted(self.run_main()), sorted(PHASES))

    def test_policies_are_swept_last(self):
        """
        Test that the managed-policy sweep runs after every principal sweep.

        A policy cannot be deleted while a user, role, or group still has it
        attached, and it is the principal sweeps that detach it. Groups were
        the one principal type swept after policies, which made a policy
        attached to a group undeletable.
        """
        calls = self.run_main()
        for principal in ("users", "roles", "groups"):
            with self.subTest(principal=principal):
                self.assertLess(
                    calls.index(principal),
                    calls.index("policies"),
                    f"{principal} must be swept before policies: a policy still "
                    f"attached to one cannot be deleted",
                )

    def test_users_are_swept_before_groups(self):
        """
        Test that the user sweep runs before the group sweep.

        A group cannot be deleted while it still has members, and it is
        cleanup_users that removes users from their groups.
        """
        calls = self.run_main()
        self.assertLess(
            calls.index("users"),
            calls.index("groups"),
            "users must be swept before groups: a group with members cannot be deleted",
        )

    def test_order_is_exactly_the_documented_one(self):
        """
        Test the full sequence, pinning it against a reordering that happens to
        satisfy each pairwise constraint above.
        """
        self.assertEqual(self.run_main(), list(PHASES))

    def test_prefix_must_be_absolute(self):
        """
        Test that a prefix not naming an absolute path is rejected.

        The prefix is the sweeper's entire ownership boundary, so a malformed
        one has to stop it rather than widen it.
        """
        with self.assertRaises(ValueError):
            self.run_main("--prefix", "no-leading-slash")

    def test_prefix_gains_a_trailing_slash(self):
        """
        Test that a prefix is normalized to end in a slash before it is used.

        Without it, `/scratchstack-e2e` would also match `/scratchstack-e2e-2/`
        and the sweep would reach outside the path it was pointed at.
        """
        seen = []

        def record(iam, prefix):
            seen.append(prefix)

        with (
            patch.object(sweep, "boto3"),
            patch.object(sys, "argv", ["sweep", "--prefix", "/some/path"]),
            patch.object(sweep, "cleanup_users", record),
            patch.object(sweep, "cleanup_roles", record),
            patch.object(sweep, "cleanup_groups", record),
            patch.object(sweep, "cleanup_policies", record),
        ):
            sweep.main()

        self.assertEqual(seen, ["/some/path/"] * len(PHASES))


class FakeIam:
    """
    An IAM client that records what it was asked to do and answers paginated
    calls from a canned set of pages.

    Only enough of the interface to drive the sweep phases: every unknown
    attribute becomes a recording no-op, so a phase calling a delete or detach
    it should not have called still shows up in `calls`.
    """

    def __init__(self, pages=None):
        self.pages = pages or {}
        self.calls = []

    def get_paginator(self, operation):
        recorder = self

        class Paginator:
            def paginate(self, **kwargs):
                recorder.calls.append((f"paginate:{operation}", kwargs))
                return recorder.pages.get(operation, [{}])

        return Paginator()

    def __getattr__(self, name):
        def operation(**kwargs):
            self.calls.append((name, kwargs))
            return {}

        return operation

    def names(self):
        """The operation names called, in order."""
        return [name for name, _ in self.calls]


class TestPolicyVersions(TestCase):
    """
    Tests that a managed policy is stripped of its extra versions before the
    sweeper tries to delete it.
    """

    #: A policy with two non-default versions alongside the default one. IAM
    #: refuses to delete a policy carrying any version but its default, and
    #: refuses to delete the default version on its own.
    POLICY_ARN = "arn:aws:iam::123456789012:policy/scratchstack-e2e/example"
    PAGES = {
        "list_policies": [{"Policies": [{"Arn": POLICY_ARN}]}],
        "list_policy_versions": [
            {
                "Versions": [
                    {"VersionId": "v1", "IsDefaultVersion": False},
                    {"VersionId": "v2", "IsDefaultVersion": True},
                    {"VersionId": "v3", "IsDefaultVersion": False},
                ]
            }
        ],
    }

    def test_non_default_versions_are_deleted_first(self):
        """
        Test that every non-default version is deleted before the policy is.

        A policy carrying more than its default version comes back
        DeleteConflict, which `eventually` retries to exhaustion and which then
        aborts the whole sweep. The suite creates extra versions, so this is
        reached by an ordinary interrupted run rather than by a corner case.
        """
        iam = FakeIam(self.PAGES)
        sweep.cleanup_policies(iam, "/scratchstack-e2e/")

        names = iam.names()
        self.assertIn("delete_policy", names)
        self.assertIn("delete_policy_version", names)
        self.assertLess(
            names.index("delete_policy_version"),
            names.index("delete_policy"),
            "versions must be deleted before the policy they belong to",
        )

    def test_only_non_default_versions_are_deleted(self):
        """
        Test that the default version is left alone.

        IAM rejects deleting the default version directly; it goes with the
        policy. Deleting it here would trade one DeleteConflict for a different
        error in the same place.
        """
        iam = FakeIam(self.PAGES)
        sweep.cleanup_policies(iam, "/scratchstack-e2e/")

        deleted = [
            kwargs["VersionId"]
            for name, kwargs in iam.calls
            if name == "delete_policy_version"
        ]
        self.assertEqual(sorted(deleted), ["v1", "v3"])

        for name, kwargs in iam.calls:
            if name == "delete_policy_version":
                self.assertEqual(kwargs["PolicyArn"], self.POLICY_ARN)

    def test_a_policy_with_only_a_default_version_deletes_no_versions(self):
        """
        Test that the common case issues no version deletions at all.
        """
        iam = FakeIam(
            {
                "list_policies": [{"Policies": [{"Arn": self.POLICY_ARN}]}],
                "list_policy_versions": [
                    {"Versions": [{"VersionId": "v1", "IsDefaultVersion": True}]}
                ],
            }
        )
        sweep.cleanup_policies(iam, "/scratchstack-e2e/")

        self.assertNotIn("delete_policy_version", iam.names())
        self.assertIn("delete_policy", iam.names())
