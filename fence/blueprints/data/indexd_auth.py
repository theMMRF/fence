"""Authentication for private IndexD record resolution."""

from fence.config import config
from fence.errors import InternalError, Unauthorized


def indexd_read_credentials(service_lookup=False):
    """Enable private lookups without changing Fence's storage authorization.

    Trusted upload/download code needs the record before checking storage access,
    including write-only users and verified GA4GH passports. Content proxying
    instead forwards the caller's JWT so IndexD filters hidden records itself.
    """
    if not config.get("INDEXD_AUTHENTICATED_READS", False):
        return {}
    if service_lookup:
        username = config.get("INDEXD_USERNAME")
        password = config.get("INDEXD_PASSWORD")
        if not username or not password:
            raise InternalError(
                "Authenticated IndexD reads require service credentials"
            )
        return {"auth": (username, password), "allow_redirects": False}
    from fence.auth import get_jwt

    try:
        token = get_jwt()
    except Unauthorized:
        token = None
    headers = {"Authorization": "Bearer " + token} if token else {}
    return {"headers": headers, "allow_redirects": False}
