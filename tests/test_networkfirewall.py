from collections import defaultdict

from botocore.exceptions import ClientError

from hyperscale.kite.networkfirewall import get_firewalls


class ListFirewallsPaginator:
    def __init__(self, firewalls, error_response=None):
        self.firewalls = firewalls
        self.error_response = error_response

    def paginate(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListFirewalls")
        firewalls = [{"FirewallArn": f["FirewallArn"]} for f in self.firewalls.values()]
        return [{"Firewalls": firewalls}]


class NetworkFirewallClient:
    def __init__(self, error_code=None):
        self.firewalls = defaultdict(dict)
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.paginators = {
            "list_firewalls": ListFirewallsPaginator(
                self.firewalls, self.error_response
            ),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def describe_firewall(self, FirewallArn):
        return {"Firewall": self.firewalls[FirewallArn]}

    def add_firewall(self, firewall_arn):
        self.firewalls[firewall_arn] = {
            "FirewallArn": firewall_arn,
            "FirewallName": "test",
            "Status": "ACTIVE",
        }


def test_get_firewalls(stub_aws_session):
    client = NetworkFirewallClient()
    stub_aws_session.register_client(client, "network-firewall", "eu-west-2")
    client.add_firewall("123456789012")
    firewalls = get_firewalls(session=stub_aws_session, region="eu-west-2")
    assert len(firewalls) == 1
    assert firewalls[0]["FirewallArn"] == "123456789012"


def test_get_firewalls_no_subscription(stub_aws_session):
    client = NetworkFirewallClient(error_code="SubscriptionRequiredException")
    stub_aws_session.register_client(client, "network-firewall", "eu-west-2")
    firewalls = get_firewalls(session=stub_aws_session, region="eu-west-2")
    assert len(firewalls) == 0
