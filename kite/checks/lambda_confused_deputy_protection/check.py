"""Check for confused deputy protection in Lambda function policies."""

from typing import Dict, Any
from kite.data import get_lambda_functions
from kite.helpers import get_account_ids_in_scope
from kite.config import Config
from kite.utils.aws_context_keys import has_confused_deputy_protection

# Define check ID and name
CHECK_ID = "lambda-confused-deputy-protection"
CHECK_NAME = "Lambda Function Confused Deputy Protection"


def _is_service_principal(principal: Any) -> bool:
    """
    Check if a principal is a service principal.

    Args:
        principal: The principal to check (can be string or list)

    Returns:
        True if the principal is a service principal, False otherwise
    """
    if isinstance(principal, list):
        return any(_is_service_principal(p) for p in principal)
    if not isinstance(principal, str):
        return False
    return principal.endswith(".amazonaws.com")


def check_lambda_confused_deputy_protection() -> Dict[str, Any]:
    """
    Check for Lambda function policies that could be vulnerable to confused deputy attacks.

    This check identifies Lambda function policies that:
    1. Allow actions to be performed by service principals
    2. Do not have proper confused deputy protection via conditions on:
       - aws:SourceAccount
       - aws:SourceArn
       - aws:SourceOrgID
       - aws:SourceOrgPaths

    Note: Only Allow statements are considered vulnerable. Deny statements are
    considered a security control and are not flagged.

    Returns:
        Dictionary containing check results
    """
    vulnerable_functions = []
    config = Config.get()

    # Get all Lambda functions
    for account_id in get_account_ids_in_scope():
        for region in config.active_regions:
            functions = get_lambda_functions(account_id, region)

            for function in functions:
                function_arn = function["FunctionArn"]
                policy = function.get("Policy")

                if not policy:
                    continue

                for statement in policy.get("Statement", []):
                    # Skip Deny statements as they are a security control
                    if statement.get("Effect") == "Deny":
                        continue

                    # Skip if statement has confused deputy protection
                    if has_confused_deputy_protection(statement.get("Condition", {})):
                        continue

                    # Check principals in the statement
                    principals = []
                    if "Principal" in statement:
                        if isinstance(statement["Principal"], dict):
                            principals.extend(statement["Principal"].values())
                        elif isinstance(statement["Principal"], str):
                            principals.append(statement["Principal"])

                    # Check if any principal is a service principal
                    if any(_is_service_principal(p) for p in principals):
                        vulnerable_functions.append({
                            "account_id": account_id,
                            "region": region,
                            "function_arn": function_arn,
                            "statement": statement
                        })

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL" if vulnerable_functions else "PASS",
        "details": {
            "vulnerable_functions": vulnerable_functions,
            "message": (
                f"Found {len(vulnerable_functions)} Lambda functions with policies that "
                "could be vulnerable to confused deputy attacks. These policies allow "
                "actions to be performed by service principals without proper source "
                "account/ARN/organization conditions."
            )
        }
    }


# Attach the check ID and name to the function
check_lambda_confused_deputy_protection._CHECK_ID = CHECK_ID
check_lambda_confused_deputy_protection._CHECK_NAME = CHECK_NAME
