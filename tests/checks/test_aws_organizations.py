from hyperscale.kite.checks.aws_organizations import AwsOrganizationsUsageCheck
from hyperscale.kite.checks.core import CheckStatus
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization


def test_check_aws_organizations_usage_pass():
    create_config_for_org()
    create_organization()

    result = AwsOrganizationsUsageCheck().run()

    assert result.status == CheckStatus.PASS


def test_check_aws_organizations_usage_fail():
    create_config_for_standalone_account()
    result = AwsOrganizationsUsageCheck().run()

    assert result.status == CheckStatus.FAIL
