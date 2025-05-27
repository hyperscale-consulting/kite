from kite.utils.aws_context_keys import (
    has_not_source_org_id_condition,
    has_no_source_account_condition,
)


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
