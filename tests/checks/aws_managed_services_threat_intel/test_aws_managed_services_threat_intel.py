"""Tests for AWS managed services threat intelligence check."""

from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from kite.checks.aws_managed_services_threat_intel.check import (
    check_aws_managed_services_threat_intel,
)


def test_check_aws_managed_services_threat_intel_pass():
    """Test successful AWS managed services threat intelligence check."""
    patch_path = "kite.checks.aws_managed_services_threat_intel.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "PASS",
            "details": {
                "message": (
                    "Teams effectively use AWS managed services with automatic threat "
                    "intelligence updates"
                )
            },
        }
        result = check_aws_managed_services_threat_intel()
        assert result["status"] == "PASS"
        assert (
            "Teams effectively use AWS managed services with automatic threat "
            "intelligence updates" in result["details"]["message"]
        )


def test_check_aws_managed_services_threat_intel_fail():
    """Test failed AWS managed services threat intelligence check."""
    patch_path = "kite.checks.aws_managed_services_threat_intel.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "FAIL",
            "details": {
                "message": (
                    "Teams do not effectively use AWS managed services with automatic "
                    "threat intelligence updates"
                )
            },
        }
        result = check_aws_managed_services_threat_intel()
        assert result["status"] == "FAIL"
        assert (
            "Teams do not effectively use AWS managed services with automatic threat "
            "intelligence updates" in result["details"]["message"]
        )


def test_check_aws_managed_services_threat_intel_error():
    """Test error handling in AWS managed services threat intelligence check."""
    patch_path = "kite.checks.aws_managed_services_threat_intel.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.side_effect = ClientError(
            dict(code="error", message="Test error"), "Operation"
        )
        with pytest.raises(ClientError):
            check_aws_managed_services_threat_intel()
