from hyperscale.kite.conditions import has_any_account_root_principal_condition
from hyperscale.kite.conditions import has_no_source_account_condition
from hyperscale.kite.conditions import has_not_requested_region_condition
from hyperscale.kite.conditions import has_not_source_org_id_condition


def test_has_not_source_org_id_condition():
    assert has_not_source_org_id_condition(
        {"StringNotEqualsIfExists": {"aws:SourceOrgID": "o-1234567890"}},
        "o-1234567890",
    )
    assert has_not_source_org_id_condition(
        {"StringNotEqualsIfExists": {"AWS:SourceOrgID": "o-1234567890"}},
        "o-1234567890",
    )
    assert not has_not_source_org_id_condition(
        {"StringNotEqualsIfExists": {"aws:SourceOrgID": "o-1234567890"}},
        "o-999999999",
    )
    assert not has_not_source_org_id_condition(
        {"StringEqualsIfExists": {"aws:SourceOrgID": "o-1234567890"}},
        "o-999999999",
    )


def test_has_no_source_account_condition():
    assert has_no_source_account_condition(
        {"Null": {"aws:SourceAccount": "false"}},
    )
    assert has_no_source_account_condition(
        {"Null": {"AWS:SourceAccount": "false"}},
    )
    assert not has_no_source_account_condition(
        {"Null": {"aws:SourceAccount": "true"}},
    )


def test_has_any_account_root_principal_condition():
    assert has_any_account_root_principal_condition(
        {"ArnLike": {"AWS:PrincipalArn": "arn:*:iam::*:root"}},
    )
    assert has_any_account_root_principal_condition(
        {"StringLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
    )
    assert has_any_account_root_principal_condition(
        {
            "StringLike": {
                "aws:PrincipalArn": [
                    "arn:*:iam::*:root",
                    "arn:aws:iam::111111111111:bob",
                ]
            }
        },
    )
    assert not has_any_account_root_principal_condition(
        {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}},
    )
    assert not has_any_account_root_principal_condition(
        {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::111111111111:root"}},
    )


def test_has_not_requested_region_condition():
    assert has_not_requested_region_condition(
        {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
        ["us-east-1", "us-west-2"],
    )
    assert not has_not_requested_region_condition(
        {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
        ["us-west-2"],
    )
    assert not has_not_requested_region_condition(
        {"StringNotEquals": {"aws:RequestedRegion": ["us-west-2"]}},
        ["us-east-1", "us-west-2"],
    )
    assert not has_not_requested_region_condition(
        {"StringEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
        ["us-east-1", "us-west-2"],
    )
