from typing import List, Dict, Any
from enum import Enum

import boto3

from kite import cloudfront


class Scope(Enum):
    CLOUDFRONT = "CLOUDFRONT"
    REGIONAL = "REGIONAL"


def get_web_acls(
        session: boto3.Session,
        scope: str,
        region: str,
) -> List[Dict[str, Any]]:
    client = session.client("wafv2", region_name=region)
    web_acls = []
    response = client.list_web_acls(Scope=scope)
    for web_acl in response["WebACLs"]:
        detail = get_web_acl(session, web_acl["ARN"], region)
        detail["Scope"] = scope
        if scope == Scope.REGIONAL.value:
            detail["Resources"] = get_resources_for_web_acl(client, web_acl["ARN"])
        else:
            detail["Resources"] = cloudfront.get_distributions_by_web_acl(
                session, web_acl["ARN"]
            )
        web_acls.append(detail)
    return web_acls


def get_resources_for_web_acl(client: boto3.client, web_acl_arn: str) -> List[Dict[str, Any]]:
    response = client.list_resources_for_web_acl(WebACLArn=web_acl_arn)
    return response["ResourceArns"]


def get_web_acl(session: boto3.Session, web_acl_arn: str, region: str) -> Dict[str, Any]:
    client = session.client("wafv2", region_name=region)
    response = client.get_web_acl(ARN=web_acl_arn)
    web_acl = response["WebACL"]
    web_acl["Region"] = region
    return web_acl


def get_logging_configurations(
        session: boto3.Session,
        scope: str,
        region: str
) -> List[Dict[str, Any]]:
    client = session.client("wafv2", region_name=region)
    logging_configurations = []
    response = client.list_logging_configurations(Scope=scope)
    for logging_configuration in response["LoggingConfigurations"]:
        logging_configuration["Region"] = region
        logging_configuration["Scope"] = scope
        logging_configurations.append(logging_configuration)
    return logging_configurations


def get_web_acl_for_resource(session: boto3.Session, resource_arn: str, region: str):
    client = session.client("wafv2", region_name=region)
    response = client.get_web_acl_for_resource(ResourceArn=resource_arn)
    return response["WebACL"]
