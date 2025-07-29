import boto3


def get_query_log_configs(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    """Get all query log configs in the account."""
    route53resolver = session.client("route53resolver", region_name=region)
    paginator = route53resolver.get_paginator("list_resolver_query_log_configs")
    query_log_configs = []
    for page in paginator.paginate():
        query_log_configs.extend(page.get("ResolverQueryLogConfigs", []))
    return query_log_configs


def get_resolver_query_log_config_associations(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    """Get all resolver query log config associations in the account."""
    route53resolver = session.client("route53resolver", region_name=region)
    paginator = route53resolver.get_paginator(
        "list_resolver_query_log_config_associations"
    )
    resolver_query_log_config_associations = []
    for page in paginator.paginate():
        resolver_query_log_config_associations.extend(
            page.get("ResolverQueryLogConfigAssociations", [])
        )
    return resolver_query_log_config_associations


def get_firewall_rule_groups(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    """Get all firewall rule groups in the account."""
    route53resolver = session.client("route53resolver", region_name=region)
    paginator = route53resolver.get_paginator("list_firewall_rule_groups")
    firewall_rule_groups = []
    for page in paginator.paginate():
        for firewall_rule_group in page.get("FirewallRuleGroups", []):
            firewall_rules = _get_firewall_rules(
                route53resolver, firewall_rule_group["Id"]
            )
            firewall_rule_group["FirewallRules"] = firewall_rules
            firewall_rule_groups.append(firewall_rule_group)
    return firewall_rule_groups


def _get_firewall_rules(
    route53resolver, firewall_rule_group_id: str
) -> list[dict[str, object]]:
    """Get all firewall rules in a firewall rule group."""
    paginator = route53resolver.get_paginator("list_firewall_rules")
    firewall_rules = []
    for page in paginator.paginate(FirewallRuleGroupId=firewall_rule_group_id):
        firewall_rules.extend(page.get("FirewallRules", []))
    return firewall_rules


def get_firewall_domain_lists(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    """Get all firewall domain lists in a firewall rule group."""
    route53resolver = session.client("route53resolver", region_name=region)
    paginator = route53resolver.get_paginator("list_firewall_domain_lists")
    firewall_domain_lists = []
    for page in paginator.paginate():
        for firewall_domain_list in page.get("FirewallDomainLists", []):
            if "ManagedOwnerName" not in firewall_domain_list:
                # Can only list domains for non-managed firewall domain lists
                domains = _get_firewall_domains(
                    route53resolver, firewall_domain_list["Id"]
                )
                firewall_domain_list["Domains"] = domains
            firewall_domain_lists.append(firewall_domain_list)
    return firewall_domain_lists


def _get_firewall_domains(
    route53resolver, firewall_domain_list_id: str
) -> list[dict[str, object]]:
    """Get all firewall domains in a firewall domain list."""
    paginator = route53resolver.get_paginator("list_firewall_domains")
    firewall_domains = []
    for page in paginator.paginate(FirewallDomainListId=firewall_domain_list_id):
        firewall_domains.extend(page.get("FirewallDomains", []))
    return firewall_domains


def get_firewall_rule_group_associations(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    """Get all firewall rule group associations in the account."""
    route53resolver = session.client("route53resolver", region_name=region)
    paginator = route53resolver.get_paginator("list_firewall_rule_group_associations")
    firewall_rule_group_associations = []
    for page in paginator.paginate():
        firewall_rule_group_associations.extend(
            page.get("FirewallRuleGroupAssociations", [])
        )
    return firewall_rule_group_associations
