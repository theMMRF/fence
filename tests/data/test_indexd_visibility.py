"""Private IndexD lookup does not replace Fence's signed URL authorization."""

from unittest.mock import MagicMock, patch

import pytest
from fence.blueprints.data.indexd import BlankIndex, IndexedFile
from fence.blueprints.data.indexd_auth import indexd_read_credentials
from fence.errors import InternalError, NotFound


@pytest.mark.parametrize("enabled", [True, False])
def test_authenticated_resolution_is_opt_in(app, enabled):
    values = {
        "INDEXD_AUTHENTICATED_READS": enabled,
        "INDEXD_USERNAME": "service",
        "INDEXD_PASSWORD": "test-password",
    }
    with patch("fence.blueprints.data.indexd_auth.config", values):
        expected = (
            {"auth": ("service", "test-password"), "allow_redirects": False}
            if enabled
            else {}
        )
        assert indexd_read_credentials(service_lookup=True) == expected


def test_missing_service_credentials_fail_closed(app):
    with patch(
        "fence.blueprints.data.indexd_auth.config", {"INDEXD_AUTHENTICATED_READS": True}
    ):
        with pytest.raises(InternalError):
            indexd_read_credentials(service_lookup=True)


def test_signed_url_checks_storage_grant_before_signing(app):
    record = IndexedFile("private-guid")
    record.__dict__["index_document"] = {
        "visibility": "restricted",
        "authz": ["/private"],
        "urls": ["s3://private/file"],
    }
    with patch.object(
        record, "get_authorized_with_username", return_value=(False, None)
    ), patch.object(record, "_get_signed_url") as sign:
        with pytest.raises(NotFound, match="No indexed document found"):
            record.get_signed_url("s3", "download", 300)
        sign.assert_not_called()


def test_authorized_download_preserves_standard_signing(app):
    record = IndexedFile("private-guid")
    record.__dict__["index_document"] = {
        "visibility": "restricted",
        "authz": ["/private"],
        "urls": ["s3://private/file"],
    }
    with patch.object(
        record, "get_authorized_with_username", return_value=(True, None)
    ), patch.object(record, "_get_signed_url", return_value="signed-url") as sign:
        assert record.get_signed_url("s3", "download", 300) == ("signed-url", None)
        sign.assert_called_once()


def test_index_document_uses_service_credentials(app):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "did": "private-guid",
        "visibility": "restricted",
        "authz": ["/private"],
        "urls": ["s3://private/file"],
    }
    values = {
        "INDEXD_AUTHENTICATED_READS": True,
        "INDEXD_USERNAME": "service",
        "INDEXD_PASSWORD": "test-password",
    }
    with patch("fence.blueprints.data.indexd_auth.config", values), patch(
        "fence.blueprints.data.indexd.requests.get", return_value=response
    ) as get:
        assert IndexedFile("private-guid").index_document["visibility"] == "restricted"
        assert get.call_args.kwargs["auth"] == ("service", "test-password")
        assert get.call_args.kwargs["allow_redirects"] is False
        assert get.call_args.kwargs["timeout"] == 30


@pytest.mark.parametrize(
    "discover,download", [(True, False), (False, True), (True, True), (False, False)]
)
def test_discovery_grants_do_not_replace_storage_grants(app, discover, download):
    record = IndexedFile("private-guid")
    record.__dict__["index_document"] = {
        "visibility": "restricted",
        "authz": ["/private"],
        "urls": ["s3://private/file"],
    }
    arborist = MagicMock()
    arborist.auth_mapping.return_value = {
        "/private": (
            [{"service": "indexd", "method": "read-metadata"}] if discover else []
        )
        + ([{"service": "fence", "method": "read-storage"}] if download else [])
    }
    arborist.auth_request.side_effect = lambda **kwargs: (
        kwargs["service"] == "fence"
        and kwargs["methods"] == "read-storage"
        and download
    )
    with app.test_request_context(), patch.object(app, "arborist", arborist), patch(
        "fence.blueprints.data.indexd.get_jwt", return_value="test-user"
    ), patch.object(record, "_get_signed_url", return_value="signed-url") as sign:
        if download:
            assert record.get_signed_url("s3", "download", 300) == ("signed-url", None)
            sign.assert_called_once()
        else:
            with pytest.raises(NotFound):
                record.get_signed_url("s3", "download", 300)
            sign.assert_not_called()
        arborist.auth_request.assert_called_once_with(
            jwt="test-user",
            service="fence",
            methods="read-storage",
            resources=["/private"],
        )
