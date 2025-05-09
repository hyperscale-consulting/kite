"""Lambda service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class LambdaFunction:
    """Lambda function data class."""

    function_name: str
    region: str


def get_functions(session, region: str) -> List[LambdaFunction]:
    """
    Get all Lambda functions in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of Lambda functions
    """
    lambda_client = session.client("lambda", region_name=region)
    functions = []

    response = lambda_client.list_functions()
    for function in response.get("Functions", []):
        functions.append(
            LambdaFunction(
                function_name=function.get("FunctionName"),
                region=region,
            )
        )

    return functions
