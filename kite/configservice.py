

def fetch_rules(session):
    client = session.client('config')
    paginator = client.get_paginator('describe_config_rules')
    rules = []
    for page in paginator.paginate():
        for rule in page['ConfigRules']:
            name = rule['ConfigRuleName']
            remediation_configurations = fetch_remediation_configurations(session, name)
            rule['RemediationConfigurations'] = remediation_configurations
            rules.append(rule)
    return rules


def fetch_remediation_configurations(session, name):
    client = session.client('config')
    response = client.describe_remediation_configurations(ConfigRuleNames=[name])
    return response['RemediationConfigurations']
