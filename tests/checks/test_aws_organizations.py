from hyperscale.kite.checks.aws_organizations import AwsOrganizationsUsageCheck
from hyperscale.kite.checks.core import CheckStatus
from tests.factories import config_for_org
from tests.factories import config_for_standalone_account
from tests.factories import create_organization


@config_for_org()
def test_check_aws_organizations_usage_pass():
    create_organization()

    result = AwsOrganizationsUsageCheck().run()

    assert result.status == CheckStatus.PASS


@config_for_standalone_account()
def test_check_aws_organizations_usage_fail():
    result = AwsOrganizationsUsageCheck().run()

    assert result.status == CheckStatus.FAIL
