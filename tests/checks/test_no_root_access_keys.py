from unittest.mock import patch

import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.no_root_access_keys import NoRootAccessKeysCheck
from hyperscale.kite.data import save_account_summary
from tests.factories import create_config_for_standalone_account

account_id = "123456789012"


@pytest.fixture
def check():
    return NoRootAccessKeysCheck()


@pytest.fixture
def mock_get_account_ids():
    """Mock the get_account_ids_in_scope function."""
    with patch("kite.checks.no_root_access_keys.get_account_ids_in_scope") as mock:
        mock.return_value = ["123456789012", "098765432109"]
        yield mock


@pytest.fixture
def mock_get_account_summary():
    """Mock the get_account_summary function."""
    with patch("kite.checks.no_root_access_keys.get_account_summary") as mock:
        yield mock


def test_no_root_access_keys(check):
    create_config_for_standalone_account([account_id])
    account_summary = {"AccountAccessKeysPresent": 0}
    save_account_summary(account_id, account_summary)
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert result.reason is not None
    assert result.reason == "No root access keys found in any accounts."


def test_root_access_keys_found(check):
    create_config_for_standalone_account([account_id])
    account_summary = {"AccountAccessKeysPresent": 1}
    save_account_summary(account_id, account_summary)

    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert result.reason is not None
    assert result.reason == "Root access keys found in 1 accounts."
