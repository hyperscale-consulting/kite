"""AWS Lambda functionality module."""

import json
from typing import Any

import boto3


def get_functions(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """
    Get all Lambda functions and their policies in the specified region.

    Args:
        session: A boto3 session with credentials for the target account
        region: The AWS region

    Returns:
        List of dictionaries containing function information and policies
    """
    lambda_client = session.client("lambda", region_name=region)
    functions = []

    # List all functions
    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for function in page["Functions"]:
            function_arn = function["FunctionArn"]

            # Get the resource policy
            try:
                policy = lambda_client.get_policy(FunctionName=function_arn)
                policy = json.loads(policy["Policy"])
            except lambda_client.exceptions.ResourceNotFoundException:
                policy = None

            function["Policy"] = policy
            functions.append(function)

    return functions
