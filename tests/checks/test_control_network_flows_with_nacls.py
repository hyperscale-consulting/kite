from hyperscale.kite.checks.control_network_flow_with_nacls import (
    ControlNetworkFlowWithNaclsCheck,
)
from hyperscale.kite.checks.core import CheckStatus
from tests.factories import create_config_for_standalone_account

account_id = "123456789012"
region = "eu-west-2"


def test_no_vpcs():
    create_config_for_standalone_account(
        account_ids=[account_id], active_regions=[region]
    )

    result = ControlNetworkFlowWithNaclsCheck().run()
    assert result.status == CheckStatus.PASS
    assert result.reason == "No VPCs with resources could be found"
