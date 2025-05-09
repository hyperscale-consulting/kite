"""Tests for the Service Catalog check."""

from unittest.mock import patch

from kite.checks.service_catalog.check import check_service_catalog


def test_service_catalog_pass():
    """Test the check when Service Catalog is used."""
    with patch(
        "kite.checks.service_catalog.check.manual_check",
        return_value={
            "check_id": "service-catalog",
            "check_name": "Service Catalog",
            "status": "PASS",
            "details": {
                "message": (
                    "Service Catalog or similar is used to allow teams to deploy "
                    "approved service configurations."
                ),
            },
        },
    ):
        result = check_service_catalog()

    assert result["check_id"] == "service-catalog"
    assert result["check_name"] == "Service Catalog"
    assert result["status"] == "PASS"
    assert (
        "Service Catalog or similar is used to allow teams to deploy"
        in result["details"]["message"]
    )


def test_service_catalog_fail():
    """Test the check when Service Catalog is not used."""
    with patch(
        "kite.checks.service_catalog.check.manual_check",
        return_value={
            "check_id": "service-catalog",
            "check_name": "Service Catalog",
            "status": "FAIL",
            "details": {
                "message": (
                    "Service Catalog or similar should be used to allow teams to "
                    "deploy approved service configurations."
                ),
            },
        },
    ):
        result = check_service_catalog()

    assert result["check_id"] == "service-catalog"
    assert result["check_name"] == "Service Catalog"
    assert result["status"] == "FAIL"
    assert (
        "Service Catalog or similar should be used to allow teams to deploy"
        in result["details"]["message"]
    )
