"""KMS service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class KMSKey:
    """KMS key data class."""

    key_id: str
    description: str


def get_customer_keys(session, region: str) -> List[KMSKey]:
    """
    Get all customer-managed KMS keys in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of customer-managed KMS keys
    """
    kms_client = session.client("kms", region_name=region)
    keys = []

    response = kms_client.list_keys()
    for key in response.get("Keys", []):
        key_id = key.get("KeyId")
        key_metadata = kms_client.describe_key(KeyId=key_id).get("KeyMetadata", {})
        if key_metadata.get("KeyManager") == "CUSTOMER":
            keys.append(
                KMSKey(
                    key_id=key_id,
                    description=key_metadata.get("Description", "No description"),
                )
            )

    return keys
