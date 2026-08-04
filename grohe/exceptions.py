class GroheError(Exception):
    """Base class for all errors raised by the Grohe client."""


class GroheUnauthorizedError(GroheError):
    """
    The Grohe API rejected the current access/refresh token.

    Raised for HTTP 401 responses, as well as the 403 variant Grohe returns for an
    invalid/expired token (body shape: {"errorCode": 403, "errorMessage": "..."}).
    Consumers should treat this as "credentials/token are no longer valid" and
    trigger a re-authentication, not a transient failure.
    """


class GroheForbiddenError(GroheError):
    """
    The Grohe API denied a request despite a valid token - e.g. per-endpoint rate
    limiting or an explicit access-policy deny (body shape:
    {"Message": "User is not authorized to access this resource with an explicit
    deny in an identity-based policy"}).

    This is distinct from GroheUnauthorizedError: the token itself is fine, but this
    specific request/endpoint is (likely temporarily) blocked.
    """


class GroheRateLimitError(GroheForbiddenError):
    """
    The Grohe API responded with HTTP 429 (Too Many Requests).

    A subclass of GroheForbiddenError so existing "keep last known data and back off"
    handling for that type also covers this case without any extra handling - the
    token is fine, this specific client is just being throttled.
    """


class GroheNetworkError(GroheError):
    """The underlying HTTP transport failed (connection error, timeout, ...)."""
