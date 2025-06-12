"""Check for air-gapped backup vaults."""

from typing import Dict, Any, List

from kite.data import get_backup_vaults, get_backup_protected_resources
from kite.config import Config
from kite.helpers import get_account_ids_in_scope, manual_check


CHECK_ID = "air-gapped-backup-vault"
CHECK_NAME = "Air Gapped Backup Vault"


def _get_protected_resources_for_vault(
    vault_arn: str, protected_resources: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Get all protected resources that are backed up to a specific vault.

    Args:
        vault_arn: The ARN of the backup vault
        protected_resources: List of all protected resources

    Returns:
        List of protected resources backed up to the specified vault
    """
    return [
        resource
        for resource in protected_resources
        if resource.get("LastBackupVaultArn") == vault_arn
    ]


def _is_air_gapped_vault(
    vault: Dict[str, Any], protected_resources: List[Dict[str, Any]]
) -> bool:
    """
    Check if a vault is air-gapped.

    A vault is considered air-gapped if either:
    1. It has type LOGICALLY_AIR_GAPPED_BACKUP_VAULT (AWS-owned account)
    2. It's in a different account than the protected resources
       (customer-owned account) and has a vault lock enabled

    Args:
        vault: The backup vault to check
        protected_resources: List of all protected resources

    Returns:
        bool: True if the vault is air-gapped, False otherwise
    """
    # Check if it's an AWS-owned air-gapped vault
    if vault.get("VaultType") == "LOGICALLY_AIR_GAPPED_BACKUP_VAULT":
        return True

    # For customer-owned vaults, check if they're in a different account AND have a
    # vault lock
    if not vault.get("Locked", False):
        return False

    vault_arn = vault["BackupVaultArn"]
    vault_account = vault_arn.split(":")[4]  # Extract account ID from ARN

    # Get resources backed up to this vault
    vault_resources = _get_protected_resources_for_vault(vault_arn, protected_resources)

    # If no resources are backed up to this vault, it's not air-gapped
    if not vault_resources:
        return False

    # Check if any resource is in the same account as the vault
    for resource in vault_resources:
        resource_arn = resource["ResourceArn"]
        resource_account = resource_arn.split(":")[4]  # Extract account ID from ARN
        if resource_account == vault_account:
            return False

    # If we get here, all resources are in different accounts than the vault
    return True


def check_air_gapped_backup_vault() -> Dict[str, Any]:
    """
    Check if critical resources are backed up to air-gapped vaults.

    This check verifies that:
    1. Air-gapped backup vaults exist (either AWS-owned or customer-owned)
    2. Critical resources are backed up to these vaults
    3. The backup frequency supports the defined RPO

    A vault is considered air-gapped if either:
    1. It has type LOGICALLY_AIR_GAPPED_BACKUP_VAULT (AWS-owned account)
    2. It's in a different account than the protected resources (customer-owned account)

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - air_gapped_vaults: Dict mapping account IDs to Dict mapping regions
                  to lists of air-gapped vaults and their protected resources
    """
    # Track air-gapped vaults by account and region
    air_gapped_vaults = {}
    has_air_gapped_vaults = False

    # Check each account
    for account_id in get_account_ids_in_scope():
        air_gapped_vaults[account_id] = {}

        # Check each region
        for region in Config.get().active_regions:
            # Get backup vaults and protected resources
            vaults = get_backup_vaults(account_id, region)
            protected_resources = get_backup_protected_resources(account_id, region)

            # Find air-gapped vaults
            air_gapped_vaults[account_id][region] = []
            for vault in vaults:
                if _is_air_gapped_vault(vault, protected_resources):
                    has_air_gapped_vaults = True
                    # Get protected resources for this vault
                    vault_resources = _get_protected_resources_for_vault(
                        vault["BackupVaultArn"], protected_resources
                    )
                    air_gapped_vaults[account_id][region].append(
                        {
                            "vault": vault,
                            "protected_resources": vault_resources,
                        }
                    )

    # Build message
    message = "Air Gapped Backup Vaults:\n\n"

    if not has_air_gapped_vaults:
        message += "No air-gapped backup vaults found.\n"
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": message,
                "air_gapped_vaults": air_gapped_vaults,
            },
        }

    # If we have air-gapped vaults, show their details
    for account_id, regions in air_gapped_vaults.items():
        for region, vaults in regions.items():
            if vaults:
                message += f"Account: {account_id}\n"
                message += f"Region: {region}\n"
                for vault_info in vaults:
                    vault = vault_info["vault"]
                    resources = vault_info["protected_resources"]
                    message += f"\n  Vault: {vault['BackupVaultName']}\n"
                    message += f"  ARN: {vault['BackupVaultArn']}\n"
                    message += f"  Type: {vault.get('VaultType', 'BACKUP_VAULT')}\n"
                    message += f"  Protected Resources: {len(resources)}\n"
                    for resource in resources:
                        message += f"    - {resource['ResourceArn']}\n"
                    message += "\n"

    message += (
        "Please review the above and confirm:\n"
        "1. Critical resources are backed up to an air-gapped vault\n"
        "2. The air-gapped vault is protected with a vault lock\n"
        "3. The backup frequency supports your defined RPO\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are critical resources backed up to air-gapped vaults at a frequency "
            "to support your defined RPO?"
        ),
        pass_message=(
            "Critical resources are backed up to air-gapped vaults at a frequency "
            "to support the defined RPO."
        ),
        fail_message=(
            "Critical resources should be backed up to air-gapped vaults at a "
            "frequency to support the defined RPO."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_air_gapped_backup_vault._CHECK_ID = CHECK_ID
check_air_gapped_backup_vault._CHECK_NAME = CHECK_NAME
