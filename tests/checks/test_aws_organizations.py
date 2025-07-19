from kite.checks.aws_organizations import check_aws_organizations_usage


def test_check_aws_organizations_usage_pass(organization):
    """Test the check when AWS Organizations is being used."""
    result = check_aws_organizations_usage()

    # Verify the result
    assert result["check_id"] == "aws-organizations-usage"
    assert result["check_name"] == "AWS Organizations Usage"
    assert result["status"] == "PASS"
    assert result["details"]["master_account_id"] == organization.master_account_id
    assert result["details"]["arn"] == organization.arn
    assert result["details"]["feature_set"] == organization.feature_set
    assert (
        result["details"]["message"]
        == "AWS Organizations is being used for account management."
    )


def test_check_aws_organizations_usage_fail():
    """Test the check when AWS Organizations is not being used."""
    result = check_aws_organizations_usage()

    # Verify the result
    assert result["check_id"] == "aws-organizations-usage"
    assert result["check_name"] == "AWS Organizations Usage"
    assert result["status"] == "FAIL"
    assert (
        result["details"]["message"]
        == "AWS Organizations is not being used for account management."
    )
