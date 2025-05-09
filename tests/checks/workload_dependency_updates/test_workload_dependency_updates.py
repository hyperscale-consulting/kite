"""Tests for workload and dependency updates check."""

import pytest
from unittest.mock import patch

from kite.checks.workload_dependency_updates.check import (
    check_workload_dependency_updates,
)


def test_check_workload_dependency_updates_pass():
    """Test successful workload and dependency updates check."""
    patch_path = "kite.checks.workload_dependency_updates.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "PASS",
            "details": {
                "message": (
                    "Teams have established mechanisms for quickly and safely "
                    "updating"
                )
            }
        }
        result = check_workload_dependency_updates()
        assert result["status"] == "PASS"
        assert (
            "Teams have established mechanisms for quickly and safely updating"
            in result["details"]["message"]
        )


def test_check_workload_dependency_updates_fail():
    """Test failed workload and dependency updates check."""
    patch_path = "kite.checks.workload_dependency_updates.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "FAIL",
            "details": {
                "message": (
                    "Teams lack mechanisms for quickly and safely updating"
                )
            }
        }
        result = check_workload_dependency_updates()
        assert result["status"] == "FAIL"
        assert (
            "Teams lack mechanisms for quickly and safely updating"
            in result["details"]["message"]
        )


def test_check_workload_dependency_updates_error():
    """Test error handling in workload and dependency updates check."""
    patch_path = "kite.checks.workload_dependency_updates.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.side_effect = Exception("Test error")
        with pytest.raises(Exception):
            check_workload_dependency_updates()
