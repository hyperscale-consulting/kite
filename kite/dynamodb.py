"""DynamoDB service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class DynamoDBTable:
    """DynamoDB table data class."""

    table_name: str
    region: str


def get_tables(session, region: str) -> List[DynamoDBTable]:
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
        tables.append(
            DynamoDBTable(
                table_name=table_name,
                region=region,
            )
        )

    return tables
