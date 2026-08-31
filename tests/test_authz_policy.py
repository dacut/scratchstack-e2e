"""
Tests for managed policy authorization behavior.

CreatePolicy builds the same tag request context CreateUser and CreateRole do:
aws:RequestTag/{}, aws:TagKeys, and both resource-tag spellings --
aws:ResourceTag/{} and iam:ResourceTag/{} -- the resource-tag keys despite the
policy not existing yet.

The iam: spelling is the interesting one. The IAM documentation lists the iam:
condition keys for CreateUser and CreateRole but not for CreatePolicy, and
Scratchstack follows the service rather than the documentation here. This file
is the evidence for that choice, which is why it asserts both directions: a
grant conditioned on iam:ResourceTag must allow a request carrying the tag it
names and deny one carrying a different value. An absent key could not produce
that split, since StringEquals on a key that is not in the request context
never matches.

CreatePolicyVersion is the open question this file also probes. Its tags come
from the policy being versioned rather than from the request, and the IAM
documentation lists only aws:ResourceTag/{} for it. Whether it also carries
iam:ResourceTag/{}, as CreatePolicy turns out to despite its documentation, is
not yet settled -- test_iam_resource_tag_governs_create_version is written as
the hypothesis that it does, so running it against real IAM answers the
question either way. Scratchstack currently supplies both; nothing there should
change until that test has been run against AWS.

Ordering matters in these tests. A denial means the condition failed only once
the grant carrying it is live, and a freshly attached inline policy takes time
to propagate: IAM passes through states that deny everything, and briefly one
where a statement matches before its condition applies. Every test here
therefore establishes the allow first -- `eventually` retries it until the
grant is in effect -- and only then asserts the denial, which by that point can
only be the condition talking.
"""

from json import dumps
from logging import getLogger

from scratchstack_e2e import TEST_PATH, IamTestCase, Policy, User, unique_name
from scratchstack_e2e.aspen import allow, policy
from scratchstack_e2e.retry import eventually, eventually_client_error

log = getLogger(__name__)

#: The document the created policies carry. Its contents are irrelevant to
#: these tests -- only that it is a valid policy document.
POLICY_DOCUMENT = policy(allow(action="s3:GetObject", resource="*"))

#: The document a new policy version carries. It differs from POLICY_DOCUMENT
#: only so that the version added is distinguishable from the original.
SECOND_POLICY_DOCUMENT = policy(allow(action="s3:PutObject", resource="*"))

#: The tag the grants below are conditioned on.
TAG_KEY = "TestTag1"
TAG_VALUE = "TestValue1"

#: A value the grants are never conditioned on, for the resource that must be
#: refused.
OTHER_TAG_VALUE = "SomeOtherValue"


class TestPolicyAuthorization(IamTestCase):
    """
    Tests for managed policy authorization behavior.
    """

    def create_policy(self, iam, tags=None):
        """
        Create a managed policy under the test path, returning its ARN.
        """
        policy_name = unique_name()
        kw = {"Tags": tags} if tags else {}
        log.info("Attempting to create policy %s with tags %s", policy_name, tags)
        response = iam.create_policy(
            PolicyName=policy_name,
            Path=TEST_PATH,
            PolicyDocument=dumps(POLICY_DOCUMENT),
            **kw,
        )
        log.info("Created policy %s", policy_name)
        return response["Policy"]["Arn"]

    def assert_condition_governs_create(self, condition_key):
        """
        Assert that `condition_key` is present in CreatePolicy's request
        context and carries the requested tag's value.

        The caller is granted CreatePolicy only where `condition_key` equals
        the tag value the request supplies. Creating with that tag must be
        allowed -- which also proves the grant has propagated -- and creating
        with a different value must then be denied. Were the key absent, both
        would be denied; were the condition ignored, both would be allowed.
        """
        grant = policy(
            allow(
                action=["iam:CreatePolicy", "iam:TagPolicy"],
                resource="*",
                condition={"StringEquals": {condition_key: TAG_VALUE}},
            ),
            # Deleting is only cleanup here, so its grant carries no condition.
            allow(action="iam:DeletePolicy", resource="*"),
        )

        with User(self.iam, permissions=grant) as user:
            iam = user.client("iam")

            # The allow comes first: `eventually` retries it until the grant is
            # in effect, so the denial asserted afterwards cannot be a
            # propagation artifact.
            arn = eventually(
                lambda: self.create_policy(
                    iam, tags=[{"Key": TAG_KEY, "Value": TAG_VALUE}]
                )
            )
            log.info("Deleting policy %s", arn)
            eventually(lambda: iam.delete_policy(PolicyArn=arn))

            def with_wrong_value():
                self.create_policy(
                    iam, tags=[{"Key": TAG_KEY, "Value": "SomeOtherValue"}]
                )

            eventually_client_error("AccessDenied", with_wrong_value)

    def test_aws_resource_tag_governs_create(self):
        """
        Test that CreatePolicy supplies aws:ResourceTag/{} from the tags the
        request asks for, even though the policy does not exist yet.
        """
        self.assert_condition_governs_create(f"aws:ResourceTag/{TAG_KEY}")

    def test_iam_resource_tag_governs_create(self):
        """
        Test that CreatePolicy supplies iam:ResourceTag/{} as well.

        The IAM documentation does not list the iam: condition keys for
        CreatePolicy, only for CreateUser and CreateRole. The service supplies
        it regardless, and Scratchstack matches the service; this test is what
        that decision rests on, so it is expected to pass against real IAM and
        against Scratchstack alike.
        """
        self.assert_condition_governs_create(f"iam:ResourceTag/{TAG_KEY}")

    def test_nonexistent_condition_key_denies(self):
        """
        The negative control for the two tests above.

        A condition key that cannot exist must deny whatever the request
        carries. Without this, "allowed with the matching tag" would not
        distinguish a key that is present from a condition that is being
        ignored altogether -- and the propagation states that deny everything
        would make the denial half of those tests look sound even if the key
        were absent.
        """
        grant = policy(
            allow(
                action=["iam:CreatePolicy", "iam:TagPolicy"],
                resource="*",
                condition={
                    "StringEquals": {f"iam:NoSuchKeyAtAll/{TAG_KEY}": TAG_VALUE}
                },
            ),
            # Granted unconditionally, so that it becoming usable proves the
            # document is live. Without that, the denials below would be
            # indistinguishable from the grant not having propagated.
            allow(action=["iam:DeletePolicy", "iam:ListPolicies"], resource="*"),
        )

        with User(self.iam, permissions=grant) as user:
            iam = user.client("iam")
            eventually(lambda: iam.list_policies(MaxItems=1))

            def with_matching_value():
                self.create_policy(
                    iam, tags=[{"Key": TAG_KEY, "Value": TAG_VALUE}]
                )

            eventually_client_error("AccessDenied", with_matching_value)

    def test_tags(self):
        """
        Test that creating a policy with conditions related to tags in the
        caller's IAM permissions are enforced.

        The grant names aws:RequestTag and aws:TagKeys, which CreatePolicy
        populates from the tags the request asks for; a request naming no tags
        leaves them absent, so the grant does not apply rather than matching an
        empty value.
        """
        user_permission = policy(
            allow(
                action=["iam:CreatePolicy", "iam:TagPolicy"],
                resource="*",
                condition={
                    "StringEquals": {f"aws:RequestTag/{TAG_KEY}": TAG_VALUE},
                    "ForAnyValue:StringEquals": {"aws:TagKeys": TAG_KEY},
                },
            ),
            allow(action="iam:DeletePolicy", resource="*"),
        )
        with User(self.iam, permissions=user_permission) as user:
            iam = user.client("iam")

            # Allow first, so the denial below is the condition talking rather
            # than a grant that has not propagated yet.
            arn = eventually(
                lambda: self.create_policy(
                    iam, tags=[{"Key": TAG_KEY, "Value": TAG_VALUE}]
                )
            )
            log.info("Deleting policy %s", arn)
            eventually(lambda: iam.delete_policy(PolicyArn=arn))

            def missing_tags():
                self.create_policy(iam)

            eventually_client_error("AccessDenied", missing_tags)

    # ------------------------------------------------------------------
    # CreatePolicyVersion
    #
    # Unlike CreatePolicy, the tags here belong to the policy being versioned
    # rather than to the request, so the resource-tag keys are the only ones
    # that could carry them. Each test uses two policies differing only in the
    # value of that tag: the grant must reach the one it names and not the
    # other.
    # ------------------------------------------------------------------

    def tagged_policy(self, tag_value):
        """
        A managed policy carrying TAG_KEY=tag_value, created as the admin
        principal and torn down with the test.

        The tag is applied by the creating call, so the policy is never visible
        untagged. The fixture's teardown deletes any non-default versions a
        test added before deleting the policy itself.
        """
        created = self.fixture(
            Policy(self.iam, POLICY_DOCUMENT, tags={TAG_KEY: tag_value})
        )
        log.info("Created policy %s tagged %s=%s", created.arn, TAG_KEY, tag_value)
        return created

    def create_policy_version(self, iam, policy_arn):
        """
        Add a version to an existing policy, returning its version id.

        The version is deliberately not made the default: a non-default version
        is what the Policy fixture knows how to clean up, and making it default
        would say nothing more about authorization.
        """
        log.info("Attempting to add a version to policy %s", policy_arn)
        response = iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=dumps(SECOND_POLICY_DOCUMENT),
        )
        version_id = response["PolicyVersion"]["VersionId"]
        log.info("Created version %s of policy %s", version_id, policy_arn)
        return version_id

    def assert_condition_governs_create_version(self, condition_key):
        """
        Assert that `condition_key` is present in CreatePolicyVersion's request
        context and carries the versioned policy's tag value.

        Two policies are created, tagged with different values for the same
        key, and the caller is granted CreatePolicyVersion only where
        `condition_key` equals one of them. Versioning the policy the grant
        names must be allowed -- which also proves the grant has propagated --
        and versioning the other must then be denied. Were the key absent, both
        would be denied; were the condition ignored, both would be allowed.
        """
        named = self.tagged_policy(TAG_VALUE)
        other = self.tagged_policy(OTHER_TAG_VALUE)

        grant = policy(
            allow(
                action="iam:CreatePolicyVersion",
                resource="*",
                condition={"StringEquals": {condition_key: TAG_VALUE}},
            ),
            # Granted unconditionally, so that it becoming usable proves the
            # document is live -- necessary but not sufficient, hence the
            # allow-before-deny ordering below.
            allow(action="iam:ListPolicies", resource="*"),
        )

        with User(self.iam, permissions=grant) as user:
            iam = user.client("iam")
            eventually(lambda: iam.list_policies(MaxItems=1))

            # The allow comes first and is retried until the grant is in
            # effect, so the denial afterwards cannot be a propagation
            # artifact.
            eventually(lambda: self.create_policy_version(iam, named.arn))

            def on_the_other_policy():
                self.create_policy_version(iam, other.arn)

            eventually_client_error("AccessDenied", on_the_other_policy)

    def test_aws_resource_tag_governs_create_version(self):
        """
        Test that CreatePolicyVersion supplies aws:ResourceTag/{} from the tags
        on the policy being versioned.

        This is the one the IAM documentation does list for this operation.
        """
        self.assert_condition_governs_create_version(f"aws:ResourceTag/{TAG_KEY}")

    def test_iam_resource_tag_governs_create_version(self):
        """
        Test whether CreatePolicyVersion also supplies iam:ResourceTag/{}.

        The IAM documentation lists only aws:ResourceTag/{} for this operation.
        It also omits the iam: keys for CreatePolicy, which the service supplies
        regardless -- so the documentation being silent is not evidence of
        absence, and this test is written as the hypothesis that the same holds
        here.

        Running it against real IAM settles it. Passing means the key is
        supplied and Scratchstack, which already supplies it, is correct as it
        stands. Failing at the allow -- AccessDenied on the policy the grant
        names -- means the documentation is right for this operation and
        Scratchstack supplies a key IAM does not, which would make a
        StringEquals guard match and a StringNotEquals deny guard fire where
        IAM leaves both dormant.
        """
        self.assert_condition_governs_create_version(f"iam:ResourceTag/{TAG_KEY}")

    def test_nonexistent_condition_key_denies_create_version(self):
        """
        The negative control for the two tests above.

        A condition key that cannot exist must deny CreatePolicyVersion on a
        policy carrying the tag the condition names. Without this, a denial in
        the tests above would not distinguish an absent key from a grant that
        never propagated, and an allow would not distinguish a key that is
        present from a condition being ignored.
        """
        named = self.tagged_policy(TAG_VALUE)

        grant = policy(
            allow(
                action="iam:CreatePolicyVersion",
                resource="*",
                condition={
                    "StringEquals": {f"iam:NoSuchKeyAtAll/{TAG_KEY}": TAG_VALUE}
                },
            ),
            allow(action="iam:ListPolicies", resource="*"),
        )

        with User(self.iam, permissions=grant) as user:
            iam = user.client("iam")
            eventually(lambda: iam.list_policies(MaxItems=1))

            def on_the_named_policy():
                self.create_policy_version(iam, named.arn)

            eventually_client_error("AccessDenied", on_the_named_policy)
