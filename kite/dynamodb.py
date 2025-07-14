"""DynamoDB service module for Kite."""

from dataclasses import dataclass


@dataclass
class DynamoDBTable:
    """DynamoDB table data class."""

    table_name: str
    region: str


def get_tables(session, region: str) -> list[DynamoDBTable]:
    """
    Get all DynamoDB tables in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of DynamoDB tables
    """
    dynamodb_client = session.client("dynamodb", region_name=region)
    tables = []

    response = dynamodb_client.list_tables()
    for table_name in response.get("TableNames", []):
        table = dict(
            TableName=table_name,
            Region=region,
            TimeToLiveDescription=get_ttl_status(dynamodb_client, table_name),
        )
        tables.append(table)

    return tables


def get_ttl_status(client, table_name: str) -> bool:
    """
    Get the TTL status of a DynamoDB table.

    Args:
        client: The boto3 client to use
        table_name: The name of the DynamoDB table
    """
    response = client.describe_time_to_live(TableName=table_name)
    return response.get("TimeToLiveDescription", {})
