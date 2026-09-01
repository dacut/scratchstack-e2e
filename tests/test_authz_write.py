"""
Tests for the condition keys the write operations supply.

These change an entity rather than reading one, and what they report about it
varies more than anywhere else in IAM -- the documentation draws lines here
that are hard to predict from the shape of the operation:

    PutGroupPolicy, UpdateGroup                     nothing
    PutRolePolicy, PutRolePermissionsBoundary,
      UpdateAssumeRolePolicy, UpdateRole,
      UpdateRoleDescription                         tags + boundary
    PutUserPolicy, PutUserPermissionsBoundary       tags + boundary
    UpdateUser                                      tags, boundary withheld
    TagRole, TagUser                                request tags + TagKeys +
                                                    resource tags, boundary
                                                    withheld
    UntagRole, UntagUser                            TagKeys + resource tags,
                                                    boundary withheld
    TagPolicy, UntagPolicy                          request tags + TagKeys +
                                                    both resource-tag spellings

Two of those lines are worth naming, because neither follows from the other.
PutUserPolicy reports the permissions boundary and UpdateUser does not, though
both change what the user may do; TagRole and UntagRole withhold it while
PutRolePolicy reports it.

A third line the documentation draws is deliberately not followed here. It
lists only aws:ResourceTag/${TagKey} for TagPolicy while listing both spellings
for UntagPolicy, which would leave the two halves of one tagging operation
disagreeing about a single key. The documentation is unreliable about
iam:ResourceTag on the policy APIs specifically -- CreatePolicy and
CreatePolicyVersion both supply it while being documented not to, as the tests
for those record -- so TagPolicy is asserted to supply it too.

UpdateGroup and UpdateUser are called with the name the entity already has
rather than with the rename left off. Omitting it does not mean "no rename" to
AWS: it builds the new ARN from the current path and an *empty* name, and
requires the caller to be allowed the action on that ARN as well --

    iam:UpdateGroup on resource: arn:aws:iam::...:group/scratchstack-e2e/

-- so a grant naming only the entity is refused. Naming the same name collapses
the two ARNs into one and authorizes once. Scratchstack differs here, defaulting
the new name to the current one, so it authorizes a single ARN either way;
these tests pass against both only because they name the name.

The tag operations are also the first here to take keys from the *request*:
aws:RequestTag/${TagKey} carries what the caller is applying and aws:TagKeys
the keys it names, neither of which the entity knows about. aws:TagKeys is
multivalued, so it is compared with a set operator rather than a plain one.

Where a key is said to be withheld, both halves are asserted: Null matches only
a missing key and must be allowed, StringEquals cannot match one and must be
denied. Every target in those tests carries a boundary, so an absence means the
operation withholds the key rather than there being no value to report.
"""

from json import dumps
from logging import getLogger

from scratchstack_e2e import Policy, Role, User
from scratchstack_e2e.aspen import trust_policy
from scratchstack_e2e.conditions import (
    INLINE_POLICY_NAME,
    OTHER_TAG_VALUE,
    SOME_DOCUMENT,
    TAG_KEY,
    TAG_VALUE,
    Check,
    ConditionTestCase,
)

log = getLogger(__name__)

#: A second tag key, so a Tag* request can name a key the entity does not
#: already carry without disturbing the one the conditions are written against.
APPLIED_TAG_KEY = "TestTag2"
APPLIED_TAG_VALUE = "TestValue2"

TAG_CONDITION_KEY = f"aws:ResourceTag/{TAG_KEY}"
IAM_TAG_CONDITION_KEY = f"iam:ResourceTag/{TAG_KEY}"
REQUEST_TAG_CONDITION_KEY = f"aws:RequestTag/{APPLIED_TAG_KEY}"


class TestWriteConditions(ConditionTestCase):
    """
    Tests for the condition keys the write operations supply.
    """

    # ------------------------------------------------------------------
    # Targets and payloads
    # ------------------------------------------------------------------

    @staticmethod
    def document():
        """A valid inline policy document, as the string these APIs take."""
        return dumps(SOME_DOCUMENT)

    def trust_document(self):
        """A valid trust policy, for UpdateAssumeRolePolicy."""
        return dumps(self.trust)

    @staticmethod
    def applied_tags():
        """
        The tag a Tag* request applies. It uses a second key, so applying it
        does not disturb the tag the resource-tag conditions are written
        against, and it is the key the Untag* requests remove.
        """
        return [{"Key": APPLIED_TAG_KEY, "Value": APPLIED_TAG_VALUE}]

    def tagged_target_role(self, boundary_arn):
        """A role carrying both the condition tag and the tag to be removed."""
        return self.fixture(
            Role(
                self.iam,
                self.trust,
                tags={TAG_KEY: TAG_VALUE, APPLIED_TAG_KEY: APPLIED_TAG_VALUE},
                permissions_boundary=boundary_arn,
            )
        )

    def tagged_target_user(self, boundary_arn):
        """A user carrying both the condition tag and the tag to be removed."""
        return self.fixture(
            User(
                self.iam,
                tags={TAG_KEY: TAG_VALUE, APPLIED_TAG_KEY: APPLIED_TAG_VALUE},
                permissions_boundary=boundary_arn,
            )
        )

    def tagged_target_policy(self):
        """A policy carrying both the condition tag and the tag to be removed."""
        return self.fixture(
            Policy(
                self.iam,
                SOME_DOCUMENT,
                tags={TAG_KEY: TAG_VALUE, APPLIED_TAG_KEY: APPLIED_TAG_VALUE},
            )
        )

    # ------------------------------------------------------------------
    # Groups: nothing to report
    # ------------------------------------------------------------------

    def test_group_writes_supply_no_context(self):
        """
        Test that PutGroupPolicy and UpdateGroup supply no request context.

        A group is neither taggable nor a principal, so the group ARN is the
        whole of what a policy can condition on.
        """
        unconditioned = self.target_group()
        null_checked = self.target_group()
        other = self.target_group()

        operations = [
            (
                "iam:PutGroupPolicy",
                lambda iam, g: iam.put_group_policy(
                    GroupName=g.group_name,
                    PolicyName=INLINE_POLICY_NAME,
                    PolicyDocument=self.document(),
                ),
            ),
            # Renamed to the name it already has. Leaving NewGroupName off
            # does not mean "no rename" to AWS: it builds the new ARN from the
            # current path and an empty name, and requires the caller to be
            # allowed the action on that too, so the call is refused against a
            # grant naming only the group itself. Naming the same name
            # collapses the two ARNs into one. See the module docstring.
            (
                "iam:UpdateGroup",
                lambda iam, g: iam.update_group(
                    GroupName=g.group_name, NewGroupName=g.group_name
                ),
            ),
        ]
        self.assert_operations(
            operations,
            [
                Check("no condition at all", None, unconditioned),
                self.absent(TAG_CONDITION_KEY, null_checked),
            ],
            [self.mismatched(TAG_CONDITION_KEY, TAG_VALUE, other)],
        )

    # ------------------------------------------------------------------
    # Writes that report the permissions boundary
    # ------------------------------------------------------------------

    def test_role_writes_supply_tags_and_boundary(self):
        """
        Test that the role write operations supply both resource-tag spellings
        and iam:PermissionsBoundary.

        This is what lets a policy delegate role management while requiring
        that the roles managed stay under a particular boundary, so a delegated
        administrator cannot raise a role above itself.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [self.target_role(TAG_VALUE, boundary.arn) for _ in range(3)]
        other = self.target_role(OTHER_TAG_VALUE, other_boundary.arn)

        operations = [
            (
                "iam:PutRolePermissionsBoundary",
                lambda iam, r: iam.put_role_permissions_boundary(
                    RoleName=r.role_name, PermissionsBoundary=boundary.arn
                ),
            ),
            (
                "iam:PutRolePolicy",
                lambda iam, r: iam.put_role_policy(
                    RoleName=r.role_name,
                    PolicyName=INLINE_POLICY_NAME,
                    PolicyDocument=self.document(),
                ),
            ),
            (
                "iam:UpdateAssumeRolePolicy",
                lambda iam, r: iam.update_assume_role_policy(
                    RoleName=r.role_name, PolicyDocument=self.trust_document()
                ),
            ),
            (
                "iam:UpdateRoleDescription",
                lambda iam, r: iam.update_role_description(
                    RoleName=r.role_name, Description="updated"
                ),
            ),
            (
                "iam:UpdateRole",
                lambda iam, r: iam.update_role(
                    RoleName=r.role_name, Description="updated again"
                ),
            ),
        ]
        self.assert_operations(
            operations,
            self.tag_and_boundary_checks(named, boundary.arn),
            [self.mismatched_tag(other)],
        )

    def test_user_writes_supply_tags_and_boundary(self):
        """
        Test that PutUserPolicy and PutUserPermissionsBoundary supply both
        resource-tag spellings and iam:PermissionsBoundary.
        """
        boundary = self.boundary_policy()
        other_boundary = self.boundary_policy()
        named = [self.target_user(TAG_VALUE, boundary.arn) for _ in range(3)]
        other = self.target_user(OTHER_TAG_VALUE, other_boundary.arn)

        operations = [
            (
                "iam:PutUserPermissionsBoundary",
                lambda iam, u: iam.put_user_permissions_boundary(
                    UserName=u.user_name, PermissionsBoundary=boundary.arn
                ),
            ),
            (
                "iam:PutUserPolicy",
                lambda iam, u: iam.put_user_policy(
                    UserName=u.user_name,
                    PolicyName=INLINE_POLICY_NAME,
                    PolicyDocument=self.document(),
                ),
            ),
        ]
        self.assert_operations(
            operations,
            self.tag_and_boundary_checks(named, boundary.arn),
            [self.mismatched_tag(other)],
        )

    def test_update_user_withholds_the_permissions_boundary(self):
        """
        Test that UpdateUser supplies both resource-tag spellings and not
        iam:PermissionsBoundary.

        PutUserPolicy reports the boundary and this does not, though both
        change what the user may do -- the line the documentation draws here
        does not follow from the shape of the operation, which is why it is
        asserted rather than assumed.
        """
        boundary = self.boundary_policy()
        named = [self.target_user(TAG_VALUE, boundary.arn) for _ in range(3)]
        compared = self.target_user(TAG_VALUE, boundary.arn)
        other = self.target_user(OTHER_TAG_VALUE, boundary.arn)

        def invoke(iam, user):
            log.info("Attempting to update user %s", user.user_name)
            # Renamed to the name it already has, for the reason UpdateGroup is
            # above: omitting NewUserName has AWS authorize against an ARN with
            # the path and an empty name as well as against the user's own.
            iam.update_user(UserName=user.user_name, NewUserName=user.user_name)

        self.assert_conditions(
            "iam:UpdateUser",
            self.tag_checks(named)
            + [self.absent("iam:PermissionsBoundary", named[2])],
            [
                self.mismatched("iam:PermissionsBoundary", boundary.arn, compared),
                self.mismatched_tag(other),
            ],
            invoke,
        )

    # ------------------------------------------------------------------
    # Tagging and untagging: keys from the request as well as the entity
    # ------------------------------------------------------------------

    def tag_checks_with_request(self, named):
        """
        The keys a Tag* request reports: what it is applying, the keys it
        names, and the tags the entity already carries.
        """
        return [
            self.supplied(
                REQUEST_TAG_CONDITION_KEY, APPLIED_TAG_VALUE, named[0]
            ),
            self.multivalued("aws:TagKeys", APPLIED_TAG_KEY, named[1]),
            self.supplied(TAG_CONDITION_KEY, TAG_VALUE, named[2]),
            self.supplied(IAM_TAG_CONDITION_KEY, TAG_VALUE, named[3]),
        ]

    def untag_checks(self, named):
        """
        The keys an Untag* request reports. There is no aws:RequestTag: the
        request names keys to remove and no values to give them.
        """
        return [
            self.multivalued("aws:TagKeys", APPLIED_TAG_KEY, named[0]),
            self.supplied(TAG_CONDITION_KEY, TAG_VALUE, named[1]),
            self.supplied(IAM_TAG_CONDITION_KEY, TAG_VALUE, named[2]),
        ]

    def test_tag_role_supplies_request_and_resource_tags(self):
        """
        Test that TagRole reports the tags being applied, the keys it names,
        and the tags the role already carries -- but not the permissions
        boundary set on it, which PutRolePolicy does report.
        """
        boundary = self.boundary_policy()
        named = [self.target_role(TAG_VALUE, boundary.arn) for _ in range(5)]
        compared = self.target_role(TAG_VALUE, boundary.arn)
        other = self.target_role(OTHER_TAG_VALUE, boundary.arn)

        def invoke(iam, role):
            log.info("Attempting to tag role %s", role.role_name)
            iam.tag_role(RoleName=role.role_name, Tags=self.applied_tags())

        self.assert_conditions(
            "iam:TagRole",
            self.tag_checks_with_request(named)
            + [self.absent("iam:PermissionsBoundary", named[4])],
            [
                self.mismatched("iam:PermissionsBoundary", boundary.arn, compared),
                self.mismatched_tag(other),
            ],
            invoke,
        )

    def test_untag_role_supplies_tag_keys_and_resource_tags(self):
        """
        Test that UntagRole reports the keys being removed and the tags the
        role carries, and withholds the permissions boundary.
        """
        boundary = self.boundary_policy()
        named = [self.tagged_target_role(boundary.arn) for _ in range(4)]
        compared = self.tagged_target_role(boundary.arn)
        other = self.target_role(OTHER_TAG_VALUE, boundary.arn)

        def invoke(iam, role):
            log.info("Attempting to untag role %s", role.role_name)
            iam.untag_role(RoleName=role.role_name, TagKeys=[APPLIED_TAG_KEY])

        self.assert_conditions(
            "iam:UntagRole",
            self.untag_checks(named)
            + [self.absent("iam:PermissionsBoundary", named[3])],
            [
                self.mismatched("iam:PermissionsBoundary", boundary.arn, compared),
                self.mismatched_tag(other),
            ],
            invoke,
        )

    def test_tag_user_supplies_request_and_resource_tags(self):
        """
        Test that TagUser reports the tags being applied, the keys it names,
        and the tags the user already carries -- but not the permissions
        boundary set on it.
        """
        boundary = self.boundary_policy()
        named = [self.target_user(TAG_VALUE, boundary.arn) for _ in range(5)]
        compared = self.target_user(TAG_VALUE, boundary.arn)
        other = self.target_user(OTHER_TAG_VALUE, boundary.arn)

        def invoke(iam, user):
            log.info("Attempting to tag user %s", user.user_name)
            iam.tag_user(UserName=user.user_name, Tags=self.applied_tags())

        self.assert_conditions(
            "iam:TagUser",
            self.tag_checks_with_request(named)
            + [self.absent("iam:PermissionsBoundary", named[4])],
            [
                self.mismatched("iam:PermissionsBoundary", boundary.arn, compared),
                self.mismatched_tag(other),
            ],
            invoke,
        )

    def test_untag_user_supplies_tag_keys_and_resource_tags(self):
        """
        Test that UntagUser reports the keys being removed and the tags the
        user carries, and withholds the permissions boundary.
        """
        boundary = self.boundary_policy()
        named = [self.tagged_target_user(boundary.arn) for _ in range(4)]
        compared = self.tagged_target_user(boundary.arn)
        other = self.target_user(OTHER_TAG_VALUE, boundary.arn)

        def invoke(iam, user):
            log.info("Attempting to untag user %s", user.user_name)
            iam.untag_user(UserName=user.user_name, TagKeys=[APPLIED_TAG_KEY])

        self.assert_conditions(
            "iam:UntagUser",
            self.untag_checks(named)
            + [self.absent("iam:PermissionsBoundary", named[3])],
            [
                self.mismatched("iam:PermissionsBoundary", boundary.arn, compared),
                self.mismatched_tag(other),
            ],
            invoke,
        )

    def test_tag_policy_supplies_request_and_resource_tags(self):
        """
        Test that TagPolicy reports the tags being applied, the keys it names,
        and the policy's own tags through both resource-tag spellings.

        The documentation lists only aws:ResourceTag/${TagKey} here, which
        would leave the two halves of one tagging operation disagreeing about a
        single key -- UntagPolicy is documented to report both. It does not:
        the documentation is unreliable about iam:ResourceTag on the policy
        APIs specifically, having already proved wrong for CreatePolicy and
        CreatePolicyVersion, both of which supply the key while being
        documented not to. This follows the service, as those two do.
        """
        named = [self.target_policy(TAG_VALUE) for _ in range(4)]
        other = self.target_policy(OTHER_TAG_VALUE)

        def invoke(iam, managed_policy):
            log.info("Attempting to tag policy %s", managed_policy.arn)
            iam.tag_policy(PolicyArn=managed_policy.arn, Tags=self.applied_tags())

        self.assert_conditions(
            "iam:TagPolicy",
            [
                self.supplied(
                    REQUEST_TAG_CONDITION_KEY, APPLIED_TAG_VALUE, named[0]
                ),
                self.multivalued("aws:TagKeys", APPLIED_TAG_KEY, named[1]),
                self.supplied(TAG_CONDITION_KEY, TAG_VALUE, named[2]),
                self.supplied(IAM_TAG_CONDITION_KEY, TAG_VALUE, named[3]),
            ],
            [self.mismatched_tag(other)],
            invoke,
        )

    def test_untag_policy_supplies_both_resource_tag_spellings(self):
        """
        Test that UntagPolicy reports the keys being removed and the policy's
        tags through both resource-tag spellings -- the iam: one that TagPolicy
        is documented to withhold.
        """
        named = [self.tagged_target_policy() for _ in range(3)]
        other = self.target_policy(OTHER_TAG_VALUE)

        def invoke(iam, managed_policy):
            log.info("Attempting to untag policy %s", managed_policy.arn)
            iam.untag_policy(
                PolicyArn=managed_policy.arn, TagKeys=[APPLIED_TAG_KEY]
            )

        self.assert_conditions(
            "iam:UntagPolicy",
            self.untag_checks(named),
            [self.mismatched_tag(other)],
            invoke,
        )
