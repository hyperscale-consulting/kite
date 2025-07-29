from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_backup_protected_resources
from hyperscale.kite.data import get_backup_vaults
from hyperscale.kite.helpers import get_account_ids_in_scope


class AirGappedBackupVaultCheck:
    def __init__(self):
        self.check_id = "air-gapped-backup-vault"
        self.check_name = "Air Gapped Backup Vault"

    @property
    def question(self) -> str:
        return (
            "Are critical resources backed up to air-gapped vaults at a frequency "
            "to support your defined RPO?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that critical resources are backed up to air-gapped "
            "vaults (either AWS-owned or customer-owned) and that the backup frequency "
            "supports the defined RPO."
        )

    def _get_protected_resources_for_vault(self, vault_arn, protected_resources):
        return [
            resource
            for resource in protected_resources
            if resource.get("LastBackupVaultArn") == vault_arn
        ]

    def _is_air_gapped_vault(self, vault, protected_resources):
        if vault.get("VaultType") == "LOGICALLY_AIR_GAPPED_BACKUP_VAULT":
            return True
        if not vault.get("Locked", False):
            return False
        vault_arn = vault["BackupVaultArn"]
        vault_account = vault_arn.split(":")[4]
        vault_resources = self._get_protected_resources_for_vault(
            vault_arn, protected_resources
        )
        if not vault_resources:
            return False
        for resource in vault_resources:
            resource_arn = resource["ResourceArn"]
            resource_account = resource_arn.split(":")[4]
            if resource_account == vault_account:
                return False
        return True

    def run(self) -> CheckResult:
        air_gapped_vaults = {}
        has_air_gapped_vaults = False
        for account_id in get_account_ids_in_scope():
            air_gapped_vaults[account_id] = {}
            for region in Config.get().active_regions:
                vaults = get_backup_vaults(account_id, region)
                protected_resources = get_backup_protected_resources(account_id, region)
                air_gapped_vaults[account_id][region] = []
                for vault in vaults:
                    if self._is_air_gapped_vault(vault, protected_resources):
                        has_air_gapped_vaults = True
                        vault_resources = self._get_protected_resources_for_vault(
                            vault["BackupVaultArn"], protected_resources
                        )
                        air_gapped_vaults[account_id][region].append(
                            {
                                "vault": vault,
                                "protected_resources": vault_resources,
                            }
                        )
        message = "Air Gapped Backup Vaults:\n\n"
        if not has_air_gapped_vaults:
            message += "No air-gapped backup vaults found.\n"
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="No air-gapped backup vaults found.",
                context=message,
                details={
                    "air_gapped_vaults": air_gapped_vaults,
                },
            )
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
            "1. Critical resources are backed up to a logically air-gapped vault (i.e. "
            "in a different AWS account to the protected resources)\n"
            "2. The air-gapped vault is protected with a vault lock\n"
            "3. The backup frequency supports your defined RPO\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
            details={
                "air_gapped_vaults": air_gapped_vaults,
            },
        )
