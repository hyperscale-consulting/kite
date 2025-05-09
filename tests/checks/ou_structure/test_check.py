"""Tests for the OU Structure check."""

from unittest.mock import patch, MagicMock

from kite.checks.ou_structure.check import check_ou_structure


def test_check_ou_structure_no_org():
    """Test the check when AWS Organizations is not being used."""
    # Mock the get_organization function to return None
    with patch("kite.checks.ou_structure.check.get_organization", return_value=None):
        result = check_ou_structure()

    # Verify the result
    assert result["check_id"] == "ou-structure"
    assert result["check_name"] == "OU Structure"
    assert result["status"] == "FAIL"
    assert (
        "AWS Organizations is not being used, so OU structure "
        "cannot be assessed." in result["details"]["message"]
    )


def test_check_ou_structure_pass():
    """Test the check when OU structure is effective."""
    # Create a mock organization object
    mock_org = MagicMock()

    # Mock the get_organization function to return our mock organization
    with patch(
        "kite.checks.ou_structure.check.get_organization", return_value=mock_org
    ):
        # Mock the get_organization_structure_str function
        with patch(
            "kite.checks.ou_structure.check.get_organization_structure_str",
            return_value="Mock Organization Structure",
        ):
            # Mock the manual_check function to return a PASS result
            with patch(
                "kite.checks.ou_structure.check.manual_check",
                return_value={
                    "check_id": "ou-structure",
                    "check_name": "OU Structure",
                    "status": "PASS",
                    "details": {
                        "message": "Effective OU structure is in place.",
                    },
                },
            ):
                result = check_ou_structure()

    # Verify the result
    assert result["check_id"] == "ou-structure"
    assert result["check_name"] == "OU Structure"
    assert result["status"] == "PASS"
    assert result["details"]["message"] == "Effective OU structure is in place."


def test_check_ou_structure_fail():
    """Test the check when OU structure is not effective."""
    # Create a mock organization object
    mock_org = MagicMock()

    # Mock the get_organization function to return our mock organization
    with patch(
        "kite.checks.ou_structure.check.get_organization", return_value=mock_org
    ):
        # Mock the get_organization_structure_str function
        with patch(
            "kite.checks.ou_structure.check.get_organization_structure_str",
            return_value="Mock Organization Structure",
        ):
            # Mock the manual_check function to return a FAIL result
            with patch(
                "kite.checks.ou_structure.check.manual_check",
                return_value={
                    "check_id": "ou-structure",
                    "check_name": "OU Structure",
                    "status": "FAIL",
                    "details": {
                        "message": "OU structure could be improved.",
                    },
                },
            ):
                result = check_ou_structure()

    # Verify the result
    assert result["check_id"] == "ou-structure"
    assert result["check_name"] == "OU Structure"
    assert result["status"] == "FAIL"
    assert result["details"]["message"] == "OU structure could be improved."
