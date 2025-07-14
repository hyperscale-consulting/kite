"""Tests for the Control Tower check."""

from unittest.mock import patch

from kite.checks.control_tower.check import check_control_tower


def test_control_tower_pass():
    """Test the check when Control Tower is used."""
    with patch(
        "kite.checks.control_tower.check.manual_check",
        return_value={
            "check_id": "control-tower",
            "check_name": "Control Tower",
            "status": "PASS",
            "details": {
                "message": (
                    "Control Tower is used to enable suitable standard controls."
                ),
            },
        },
    ):
        result = check_control_tower()

    assert result["check_id"] == "control-tower"
    assert result["check_name"] == "Control Tower"
    assert result["status"] == "PASS"
    assert (
        "Control Tower is used to enable suitable standard controls"
        in result["details"]["message"]
    )


def test_control_tower_fail():
    """Test the check when Control Tower is not used."""
    with patch(
        "kite.checks.control_tower.check.manual_check",
        return_value={
            "check_id": "control-tower",
            "check_name": "Control Tower",
            "status": "FAIL",
            "details": {
                "message": (
                    "Control Tower should be used to enable suitable standard controls."
                ),
            },
        },
    ):
        result = check_control_tower()

    assert result["check_id"] == "control-tower"
    assert result["check_name"] == "Control Tower"
    assert result["status"] == "FAIL"
    assert (
        "Control Tower should be used to enable suitable standard controls"
        in result["details"]["message"]
    )
