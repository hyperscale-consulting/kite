from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_kms_keys
from hyperscale.kite.helpers import get_account_ids_in_scope


def _keys_with_origin(keys: list[dict], origins: list[str]) -> list[dict]:
    return [key for key in keys if key.get("Origin") in origins]


def _get_customer_managed_keys(account: str, region: str) -> list[dict]:
    return [k for k in get_kms_keys(account, region) if k["KeyManager"] == "CUSTOMER"]


class UseAKmsCheck:
    def __init__(self):
        self.check_id = "use-a-kms"
        self.check_name = "Use a KMS"

    @property
    def question(self) -> str:
        return (
            "Are all keys stored in a Key Management System using hardware "
            "security modules to protect keys?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that all keys are stored in a Key Management "
            "System using hardware security modules to protect keys."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        accounts = get_account_ids_in_scope()

        all_keys = defaultdict(dict)
        for account in accounts:
            for region in config.active_regions:
                keys = _get_customer_managed_keys(account, region)
                if keys:
                    all_keys[account][region] = keys

        message = (
            "All keys should be stored in a KMS using HSMs to protect keys.\n\n"
            "This includes keys used by workloads, which should be envelope encrypted "
            "with a key that is stored in a HSM-backed KMS.\n\n"
            "In AWS, there are 4 possible origins of key material:\n"
            "- AWS KMS: key material is generated and stored in AWS managed HSM "
            "appliances.\n"
            "- AWS CloudHSM: key material is generated and stored in customer-managed "
            "AWS CloudHSM clusters.\n"
            "- External key store: key material is generated and stored outside of "
            "AWS, in customer-managed HSMs.\n"
            "- External: key material is generated externally and the imported into "
            "AWS KMS. This type should be avoided where possible because copies may "
            "exist outside of a HSM.\n\n"
        )
        if all_keys:
            message += "The following AWS KMS keys were found in in-scope accounts:\n\n"
            for account_id, regions in all_keys.items():
                message += f"\nAccount: {account_id}\n"
                for region, keys in regions.items():
                    message += f"\n  Region: {region}\n"
                    hsm_keys = _keys_with_origin(
                        keys, ["AWS_KMS", "AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"]
                    )
                    if hsm_keys:
                        message += "    ✅ Keys stored and generated in a HSM:\n"
                        for k in hsm_keys:
                            message += f"    - {k['KeyId']} (Origin {k['Origin']})\n"
                    external_keys = _keys_with_origin(keys, ["EXTERNAL"])
                    if external_keys:
                        message += "    ⚠️ Keys generated outside of a HSM:\n"
                        for k in external_keys:
                            message += f"    - {k['KeyId']} (Origin {k['Origin']})\n"

        else:
            message += (
                "⚠️ No customer-managed AWS KMS keys could be found in any "
                "in-scope account.\n"
            )

        message += (
            "\nEnsure that any keys not created in AWS KMS (such as workload "
            "data keys) are stored in a HSM or envelope encrypted by a master key "
            "stored in a HSM.\n"
        )

        return CheckResult(status=CheckStatus.MANUAL, context=message)
