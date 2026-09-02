"""
Tests that the package exports what its __all__ claims.

These need no AWS credentials and no endpoint -- they import the package and
look at what the names are bound to. They exist because one of those bindings
was quietly wrong: the module holding the Policy fixture was named policy.py,
and importing a submodule binds it as an attribute of its package, so
`scratchstack_e2e.policy` was the module rather than the policy() helper
re-exported from .aspen.

That failure is worth guarding against by shape rather than by name. It is
invisible to every check short of calling the thing: the import succeeds, the
name is bound, pytest collects the module without complaint, and only the call
site raises -- "'module' object is not callable", from a line that looks
correct and reads correctly. A test that merely imported the package would
still have passed.

Any submodule whose name collides with an exported helper reintroduces it, so
the assertion is written against every entry in __all__ rather than against
`policy` alone.
"""

import inspect
from types import ModuleType
from unittest import TestCase

import scratchstack_e2e
from scratchstack_e2e import aspen

#: Exported names that must be callable helpers rather than modules or classes.
#: Each is also re-exported from a submodule, which is where the collision risk
#: comes from -- a name here that matches a module name under the package will
#: be shadowed by it.
HELPERS = ("allow", "deny", "policy", "statement", "trust_policy", "unique_name")


class TestPackageExports(TestCase):
    """
    Tests that the package exports what its __all__ claims.
    """

    def test_all_names_are_importable(self):
        """
        Test that every name in __all__ is actually bound on the package.
        """
        for name in scratchstack_e2e.__all__:
            with self.subTest(name=name):
                self.assertTrue(
                    hasattr(scratchstack_e2e, name),
                    f"{name!r} is listed in __all__ but not bound on the package",
                )

    def test_no_export_is_shadowed_by_a_submodule(self):
        """
        Test that no exported name is bound to a module.

        Importing a submodule binds it as an attribute of its package, so a
        submodule sharing a name with an exported helper replaces it. Nothing
        in __all__ is meant to be a module, which makes "is it a module" a
        sufficient and name-independent test for that whole class of mistake.
        """
        for name in scratchstack_e2e.__all__:
            with self.subTest(name=name):
                value = getattr(scratchstack_e2e, name)
                bound_to = getattr(value, "__name__", "?")
                self.assertNotIsInstance(
                    value,
                    ModuleType,
                    f"{name!r} is bound to the module {bound_to!r} rather than "
                    f"the object __all__ names. A submodule of the same name is "
                    f"shadowing it; rename the submodule.",
                )

    def test_helpers_are_the_functions_they_name(self):
        """
        Test that the policy-construction helpers are callable, and are the
        same objects .aspen defines.

        The shadowing case is caught above, but a helper could also be bound to
        a stale or wrong object; asserting identity against the defining module
        pins what the package re-exports rather than only what type it is.
        """
        for name in HELPERS:
            with self.subTest(name=name):
                value = getattr(scratchstack_e2e, name)
                self.assertTrue(callable(value), f"{name!r} is not callable")

                defined = getattr(aspen, name, None)
                if defined is not None:
                    self.assertIs(
                        value,
                        defined,
                        f"{name!r} is not the object scratchstack_e2e.aspen defines",
                    )

    def test_policy_builds_a_document(self):
        """
        Test that the exported policy() helper actually builds a document.

        The regression that prompted these tests raised only at the call site,
        so one call is worth more here than any amount of introspection.
        """
        document = scratchstack_e2e.policy(
            scratchstack_e2e.allow(action="iam:ListUsers")
        )
        self.assertEqual(document["Version"], "2012-10-17")
        self.assertEqual(
            document["Statement"],
            [{"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*"}],
        )

    def test_exported_fixtures_are_classes(self):
        """
        Test that the fixture names in __all__ are classes.

        Policy is the one that was shadowed, and it is exported from a module
        whose name no longer matches any helper; the rest are asserted with it
        so the check does not have to be revisited when another is added.
        """
        for name in ("Arn", "Group", "Policy", "Role", "User"):
            with self.subTest(name=name):
                value = getattr(scratchstack_e2e, name)
                self.assertTrue(inspect.isclass(value), f"{name!r} is not a class")
