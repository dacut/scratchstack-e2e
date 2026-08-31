"""
Utilities for retrying AWS API calls in the face of eventual consistency.
"""

import logging
import time

from botocore.exceptions import ClientError

#: How long `eventually` retries before giving up, in seconds.
EVENTUAL_TIMEOUT = 20.0

#: The initial backoff interval, in seconds.
EVENTUAL_INIT_BACKOFF = 0.5

#: The maximum backoff interval, in seconds.
EVENTUAL_MAX_BACKOFF = 5.0

#: The multiplier applied to the backoff interval after each retry.
EVENTUAL_BACKOFF_MULTIPLIER = 1.5

log = logging.getLogger(__name__)


def eventually(probe, *, timeout=EVENTUAL_TIMEOUT):
    """
    Call `probe` until it returns without raising ClientError, and
    return its value.

    Only for propagation delays on real AWS -- newly created credentials,
    newly attached policies. Never use it to paper over a Scratchstack
    response that should already be correct: it will turn a real bug into a
    slow test.
    """
    deadline = time.monotonic() + timeout
    interval = EVENTUAL_INIT_BACKOFF
    while True:
        try:
            return probe()
        except ClientError as e:
            if time.monotonic() >= deadline:
                raise
            error = e.response.get("Error")
            assert isinstance(error, dict)
            code = error.get("Code")
            log.info("Error %s encountered, will retry in %s seconds", code, interval)
            time.sleep(interval)
            interval = min(interval * EVENTUAL_BACKOFF_MULTIPLIER, EVENTUAL_MAX_BACKOFF)


def eventually_client_error(code, probe, *, timeout=EVENTUAL_TIMEOUT):
    """
    Call `probe` until it raises a ClientError with the given code, and
    return the exception.

    The counterpart to `eventually` for assertions that expect a denial.
    Wrapping such a call in `assertClientError(...)` around `eventually`
    instead would retry the *expected* error until the timeout expired,
    turning every negative authorization test into a 30 second one.
    """
    deadline = time.monotonic() + timeout
    interval = EVENTUAL_INIT_BACKOFF
    while True:
        try:
            probe()
        except ClientError as e:
            error = e.response.get("Error")
            assert isinstance(error, dict)
            actual_code = error.get("Code")

            if actual_code == code:
                return e
            if time.monotonic() >= deadline:
                raise
            log.info(
                "Expected ClientError with code %s, but got %s; will retry in %s seconds",
                code,
                actual_code,
                interval,
            )
        else:
            if time.monotonic() >= deadline:
                raise AssertionError(f"Expected {code}, but the call succeeded")
            log.info(
                "Call succeeded, but expected ClientError with code %s; will retry in %s seconds",
                code,
                interval,
            )
        time.sleep(interval)
        interval = min(interval * EVENTUAL_BACKOFF_MULTIPLIER, EVENTUAL_MAX_BACKOFF)
