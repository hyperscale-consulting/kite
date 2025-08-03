import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.use_route53resolver_dns_firewall import (
    UseRoute53ResolverDnsFirewallCheck,
)
from hyperscale.kite.data import save_ec2_instances
from hyperscale.kite.data import save_route53resolver_firewall_domain_lists
from hyperscale.kite.data import save_route53resolver_firewall_rule_group_associations
from hyperscale.kite.data import save_route53resolver_firewall_rule_groups
from hyperscale.kite.data import save_vpcs
from tests.factories import build_dns_firewall_domain_list
from tests.factories import build_dns_firewall_rule
from tests.factories import build_dns_firewall_rule_group
from tests.factories import build_dns_firewall_rule_group_association
from tests.factories import create_config_for_org
from tests.factories import create_organization_with_workload_account

mgmt_account_id = "123456789012"
workload_account_id = "999999999999"
region = "eu-west-2"


@pytest.fixture
def check():
    return UseRoute53ResolverDnsFirewallCheck()


def test_run_no_vpcs_with_resources(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization_with_workload_account(mgmt_account_id, workload_account_id)
    result = check.run()

    assert result.status == CheckStatus.PASS
    assert result.reason is not None
    assert "No VPCs with resources found" in result.reason


def test_run_vpcs_with_resources_and_dns_firewall(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization_with_workload_account(mgmt_account_id, workload_account_id)

    vpcs = [
        {"VpcId": "no-firewall"},
        {"VpcId": "no-resources"},
        {"VpcId": "dns-firewall"},
    ]
    save_vpcs(workload_account_id, region, vpcs)

    ec2_instances = [{"VpcId": "no-firewall"}, {"VpcId": "dns-firewall"}]
    save_ec2_instances(workload_account_id, region, ec2_instances)

    dns_firewalls = [
        build_dns_firewall_rule_group(
            "foo_frg",
            rules=[build_dns_firewall_rule(domain_list_id="foo_domain_list_id")],
        )
    ]
    save_route53resolver_firewall_rule_groups(
        workload_account_id, region, dns_firewalls
    )

    domain_lists = [build_dns_firewall_domain_list("foo_domain_list")]
    save_route53resolver_firewall_domain_lists(
        workload_account_id, region, domain_lists
    )

    associations = [
        build_dns_firewall_rule_group_association(
            vpc_id="dns-firewall", rule_group_id="foo_frg"
        )
    ]
    save_route53resolver_firewall_rule_group_associations(
        workload_account_id, region, associations
    )

    result = check.run()

    assert result.status == CheckStatus.MANUAL
    assert result.context is not None
    print(result.context)
    assert f"Account: {workload_account_id}" in result.context
    assert "Total VPCs with resources: 2" in result.context
    assert "VPCs with DNS firewall: 1" in result.context
    assert "VPCs without DNS firewall: 1" in result.context
