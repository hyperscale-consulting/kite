from kite.utils.aws_context_keys import has_not_source_org_id_condition


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
