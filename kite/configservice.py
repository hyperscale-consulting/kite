def fetch_rules(session, region):
    client = session.client("config", region_name=region)
    paginator = client.get_paginator("describe_config_rules")
    rules = []
    rule_names = []

    # First, collect all rules and their names
    for page in paginator.paginate():
        for rule in page["ConfigRules"]:
            rules.append(rule)
            rule_names.append(rule["ConfigRuleName"])

    # Batch fetch all remediation configurations in chunks of 25 (API limit)
    if rule_names:
        all_remediation_configs = []
        # Process in chunks of 25 to respect API limits
        chunk_size = 25
        for i in range(0, len(rule_names), chunk_size):
            chunk = rule_names[i : i + chunk_size]
            chunk_configs = fetch_remediation_configurations(session, chunk)
            all_remediation_configs.extend(chunk_configs)

        # Create a mapping of rule name to remediation configurations
        remediation_map = {}
        for config in all_remediation_configs:
            remediation_map[config["ConfigRuleName"]] = config

        # Attach remediation configurations to each rule
        for rule in rules:
            rule_name = rule["ConfigRuleName"]
            rule["RemediationConfigurations"] = remediation_map.get(rule_name, [])

    return rules


def fetch_remediation_configurations(session, rule_names):
    client = session.client("config")
    response = client.describe_remediation_configurations(ConfigRuleNames=rule_names)
    return response["RemediationConfigurations"]


def fetch_compliance_by_rule(session, region):
    client = session.client("config", region_name=region)
    paginator = client.get_paginator("describe_compliance_by_config_rule")
    compliance = []
    for page in paginator.paginate():
        for item in page["ComplianceByConfigRules"]:
            compliance.append(item)
    return compliance


def fetch_recorders(session, region):
    client = session.client("config", region_name=region)
    response = client.describe_configuration_recorders()
    return response["ConfigurationRecorders"]


def fetch_delivery_channels(session, region):
    client = session.client("config", region_name=region)
    response = client.describe_delivery_channels()
    return response["DeliveryChannels"]
