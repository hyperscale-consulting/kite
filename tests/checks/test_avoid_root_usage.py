from datetime import datetime
from datetime import timezone

import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.avoid_root_usage import AvoidRootUsageCheck
from hyperscale.kite.data import save_credentials_report
from tests.factories import create_config_for_org
from tests.factories import create_organization_with_workload_account

mgmt_account_id = "1111111111111"
workload_account_id = "2222222222222"


@pytest.fixture
def check():
    return AvoidRootUsageCheck()


def test_check_root_not_used(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization_with_workload_account(mgmt_account_id, workload_account_id)
    credentials_report = {
        "root": {"user": "<root_account>", "password_last_used": "no_information"}
    }
    save_credentials_report(workload_account_id, credentials_report)
    save_credentials_report(mgmt_account_id, credentials_report)
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_check_root_used(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization_with_workload_account(mgmt_account_id, workload_account_id)
    workload_credentials_report = {
        "root": {"user": "<root_account>", "password_last_used": "no_information"}
    }
    save_credentials_report(workload_account_id, workload_credentials_report)
    mgmt_account_credentials_report = {
        "root": {
            "user": "<root_account>",
            "password_last_used": datetime.now(timezone.utc).isoformat(),
        }
    }
    save_credentials_report(mgmt_account_id, mgmt_account_credentials_report)
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert result.reason is not None
    assert (
        result.reason
        == "Root account password has been used in the last 90 days in 1 account(s)."
    )
    assert result.details == {
        "accounts_with_root_usage": [
            {
                "account_id": mgmt_account_id,
                "password_last_used": mgmt_account_credentials_report["root"][
                    "password_last_used"
                ],
            }
        ]
    }
