from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from kite.checks.tech_inventories_scanned.check import check_tech_inventories_scanned


def test_check_tech_inventories_scanned_pass():
    """Test successful technology inventory scanning check."""
    patch_path = "kite.checks.tech_inventories_scanned.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "PASS",
            "details": {
                "message": "Teams maintain comprehensive technology inventories"
            },
        }
        result = check_tech_inventories_scanned()
        assert result["status"] == "PASS"
        assert (
            "Teams maintain comprehensive technology inventories"
            in result["details"]["message"]
        )


def test_check_tech_inventories_scanned_fail():
    """Test failed technology inventory scanning check."""
    patch_path = "kite.checks.tech_inventories_scanned.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "FAIL",
            "details": {
                "message": "Teams do not maintain complete technology inventories"
            },
        }
        result = check_tech_inventories_scanned()
        assert result["status"] == "FAIL"
        assert (
            "Teams do not maintain complete technology inventories"
            in result["details"]["message"]
        )


def test_check_tech_inventories_scanned_error():
    """Test error handling in technology inventory scanning check."""
    patch_path = "kite.checks.tech_inventories_scanned.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.side_effect = ClientError(
            dict(code="error", message="Test error"), "Operation"
        )
        with pytest.raises(ClientError):
            check_tech_inventories_scanned()
