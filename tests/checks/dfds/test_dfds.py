"""Tests for the Data Flow Diagrams check."""

from unittest.mock import patch

from kite.checks.dfds.check import check_dfds


def test_dfds_pass():
    """Test the check when DFDs are up-to-date."""
    with patch(
        "kite.checks.dfds.check.manual_check",
        return_value={
            "check_id": "dfds",
            "check_name": "Data Flow Diagrams",
            "status": "PASS",
            "details": {
                "message": (
                    "There are up-to-date DFDs capturing all major trust boundaries, "
                    "data flows and components."
                ),
            },
        },
    ):
        result = check_dfds()

    assert result["check_id"] == "dfds"
    assert result["check_name"] == "Data Flow Diagrams"
    assert result["status"] == "PASS"
    assert (
        "There are up-to-date DFDs capturing all major trust boundaries"
        in result["details"]["message"]
    )


def test_dfds_fail():
    """Test the check when DFDs are not up-to-date."""
    with patch(
        "kite.checks.dfds.check.manual_check",
        return_value={
            "check_id": "dfds",
            "check_name": "Data Flow Diagrams",
            "status": "FAIL",
            "details": {
                "message": (
                    "There should be up-to-date DFDs capturing all major trust "
                    "boundaries, data flows and components."
                ),
            },
        },
    ):
        result = check_dfds()

    assert result["check_id"] == "dfds"
    assert result["check_name"] == "Data Flow Diagrams"
    assert result["status"] == "FAIL"
    assert (
        "There should be up-to-date DFDs capturing all major trust boundaries"
        in result["details"]["message"]
    )
