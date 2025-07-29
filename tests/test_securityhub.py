from botocore.exceptions import ClientError

from hyperscale.kite.securityhub import get_action_targets
from hyperscale.kite.securityhub import get_automation_rules


class ListActionTargetsPaginator:
    def __init__(self, action_targets, error_response=None):
        self.action_targets = action_targets
        self.error_response = error_response

    def paginate(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListActionTargets")
        return [{"ActionTargets": self.action_targets}]


class SecurityHubClient:
    def __init__(self, error_code=None):
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.error_code = error_code
        self.automation_rules = []
        self.action_targets = []
        self.paginators = {
            "describe_action_targets": ListActionTargetsPaginator(
                self.action_targets, self.error_response
            ),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def list_automation_rules(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListAutomationRules")
        return {"AutomationRulesMetadata": self.automation_rules}

    def add_automation_rule(self, name):
        self.automation_rules.append(
            {
                "RuleName": name,
                "RuleArn": "arn:aws:securityhub:us-east-1:123456789012:automation-rule/"
                f"a1b2c3d4-5678-90ab-cdef-{name}",
            }
        )

    def add_action_target(self, name):
        self.action_targets.append(
            {
                "ActionTargetArn": "arn:aws:securityhub:us-west-1:123456789012:action/"
                f"custom/{name}",
                "Description": "Test action target",
                "Name": name,
            }
        )


def test_get_action_targets(stub_aws_session):
    client = SecurityHubClient()
    stub_aws_session.register_client(client, "securityhub", "eu-west-2")
    client.add_action_target("TestActionTarget")
    action_targets = get_action_targets(session=stub_aws_session, region="eu-west-2")
    assert len(action_targets) == 1
    assert action_targets[0]["Name"] == "TestActionTarget"


def test_get_automation_rules(stub_aws_session):
    client = SecurityHubClient()
    stub_aws_session.register_client(client, "securityhub", "eu-west-2")
    client.add_automation_rule("TestAutomationRule")
    rules = get_automation_rules(session=stub_aws_session, region="eu-west-2")
    assert len(rules) == 1
    assert rules[0]["RuleName"] == "TestAutomationRule"


def test_get_automation_rules_no_subscription(stub_aws_session):
    client = SecurityHubClient(error_code="SubscriptionRequiredException")
    stub_aws_session.register_client(client, "securityhub", "eu-west-2")
    rules = get_automation_rules(session=stub_aws_session, region="eu-west-2")
    assert len(rules) == 0


def test_get_action_targets_no_subscription(stub_aws_session):
    client = SecurityHubClient(error_code="SubscriptionRequiredException")
    stub_aws_session.register_client(client, "securityhub", "eu-west-2")
    rules = get_action_targets(session=stub_aws_session, region="eu-west-2")
    assert len(rules) == 0
