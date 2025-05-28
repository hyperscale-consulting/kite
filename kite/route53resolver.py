import boto3
from typing import List, Dict, Any


def get_query_log_configs(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
    """Get all query log configs in the account.
    """
    route53resolver = session.client('route53resolver', region_name=region)
    paginator = route53resolver.get_paginator('list_resolver_query_log_configs')
    query_log_configs = []
    for page in paginator.paginate():
        query_log_configs.extend(page.get('ResolverQueryLogConfigs', []))
    return query_log_configs


def get_resolver_query_log_config_associations(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
    """Get all resolver query log config associations in the account.
    """
    route53resolver = session.client('route53resolver', region_name=region)
    paginator = route53resolver.get_paginator(
        'list_resolver_query_log_config_associations'
    )
    resolver_query_log_config_associations = []
    for page in paginator.paginate():
        resolver_query_log_config_associations.extend(
            page.get('ResolverQueryLogConfigAssociations', [])
        )
    return resolver_query_log_config_associations
