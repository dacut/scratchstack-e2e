#!/usr/bin/env python3
"""
Minimal ARN parsing, so tests can assert on ARN structure without hardcoding a
partition, region, or account id. The same assertion has to pass against
Scratchstack (partition "local") and against real AWS (partition "aws").
"""

from typing import Optional


class Arn:
    """
    A parsed Amazon Resource Name.
    """

    __slots__ = ("account_id", "partition", "region", "resource", "service")

    def __init__(
        self, partition: str, service: str, region: str, account_id: str, resource: str
    ):
        self.account_id = account_id
        self.partition = partition
        self.region = region
        self.resource = resource
        self.service = service

    @classmethod
    def parse(cls, arn: str) -> "Arn":
        parts = arn.split(":", 5)
        if len(parts) != 6 or parts[0] != "arn":
            raise ValueError(f"Not an ARN: {arn!r}")
        return cls(parts[1], parts[2], parts[3], parts[4], parts[5])

    def __repr__(self):
        return (
            f"arn:{self.partition}:{self.service}:{self.region}:"
            f"{self.account_id}:{self.resource}"
        )

    @property
    def resource_type(self) -> Optional[str]:
        """
        The portion of the resource before the first "/", e.g. "user" for
        "user/scratchstack-e2e/alice". None if the resource is unqualified.
        """
        head, sep, _ = self.resource.partition("/")
        return head if sep else None

    @property
    def path(self) -> Optional[str]:
        """
        The IAM path embedded in the resource, e.g. "/scratchstack-e2e/" for
        "user/scratchstack-e2e/alice". Always starts and ends with "/".
        """
        _, sep, rest = self.resource.partition("/")
        if not sep:
            return None
        path, _, _ = rest.rpartition("/")
        return f"/{path}/" if path else "/"

    @property
    def resource_name(self) -> str:
        """
        The trailing name of the resource, e.g. "alice" for
        "user/scratchstack-e2e/alice".
        """
        return self.resource.rpartition("/")[2]
