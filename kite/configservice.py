def fetch_rules(session, region):
    client = session.client("config", region_name=region)
    paginator = client.get_paginator("describe_config_rules")
    rules = []
    for page in paginator.paginate():
        for rule in page["ConfigRules"]:
            name = rule["ConfigRuleName"]
            remediation_configurations = fetch_remediation_configurations(session, name)
            rule["RemediationConfigurations"] = remediation_configurations
            rules.append(rule)
    return rules


def fetch_compliance_by_rule(session, region):
    client = session.client("config", region_name=region)
    paginator = client.get_paginator("describe_compliance_by_config_rule")
    compliance = []
    for page in paginator.paginate():
        for item in page["ComplianceByConfigRules"]:
            compliance.append(item)
    return compliance


def fetch_remediation_configurations(session, name):
    client = session.client("config")
    response = client.describe_remediation_configurations(ConfigRuleNames=[name])
    return response["RemediationConfigurations"]


def fetch_recorders(session, region):
    client = session.client("config", region_name=region)
    response = client.describe_configuration_recorders()
    return response["ConfigurationRecorders"]


def fetch_delivery_channels(session, region):
    client = session.client("config", region_name=region)
    response = client.describe_delivery_channels()
    return response["DeliveryChannels"]
