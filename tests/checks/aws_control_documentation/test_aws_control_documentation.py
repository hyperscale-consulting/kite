"""Tests for the AWS Control Documentation check."""

from unittest.mock import patch

from kite.checks.aws_control_documentation.check import check_aws_control_documentation


def test_aws_control_documentation_pass():
    """Test the check when AWS control documentation is incorporated."""
    with patch(
        "kite.checks.aws_control_documentation.check.manual_check",
        return_value={
            "check_id": "aws-control-documentation",
            "check_name": "AWS Control Documentation",
            "status": "PASS",
            "details": {
                "message": (
                    "AWS control and compliance documentation is incorporated into "
                    "control evaluation and verification procedures."
                ),
            },
        },
    ):
        result = check_aws_control_documentation()

    assert result["check_id"] == "aws-control-documentation"
    assert result["check_name"] == "AWS Control Documentation"
    assert result["status"] == "PASS"
    assert (
        "AWS control and compliance documentation is incorporated"
        in result["details"]["message"]
    )


def test_aws_control_documentation_fail():
    """Test the check when AWS control documentation is not incorporated."""
    with patch(
        "kite.checks.aws_control_documentation.check.manual_check",
        return_value={
            "check_id": "aws-control-documentation",
            "check_name": "AWS Control Documentation",
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS control and compliance documentation should be incorporated "
                    "into control evaluation and verification procedures."
                ),
            },
        },
    ):
        result = check_aws_control_documentation()

    assert result["check_id"] == "aws-control-documentation"
    assert result["check_name"] == "AWS Control Documentation"
    assert result["status"] == "FAIL"
    assert (
        "AWS control and compliance documentation should be incorporated"
        in result["details"]["message"]
    )
