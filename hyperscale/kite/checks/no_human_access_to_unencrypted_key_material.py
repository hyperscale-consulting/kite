from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_kms_keys
from hyperscale.kite.helpers import get_account_ids_in_scope


class NoHumanAccessToUnencryptedKeyMaterialCheck:
    def __init__(self):
        self.check_id = "no-human-access-to-unencrypted-key-material"
        self.check_name = "No Human Access to Unencrypted Key Material"

    @property
    def question(self) -> str:
        return "Is human access to unencrypted key material prevented for all keys?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that human access to unencrypted key material is "
            "prevented."
        )

    def _format_external_keys(
        self, keys: list[dict], account: str, region: str
    ) -> tuple[list[str], list[str]]:
        external_keys = []
        external_store_keys = []
        for key in keys:
            key_id = key.get("KeyId")
            if not key_id:
                continue
            metadata = key.get("Metadata", {})
            if metadata.get("KeyManager") != "CUSTOMER":
                continue
            formatted_key = f"  - {key_id} ({account}/{region})"
            origin = metadata.get("Origin")
            if origin == "EXTERNAL":
                external_keys.append(formatted_key)
            elif origin == "EXTERNAL_KEY_STORE":
                external_store_keys.append(formatted_key)
        return external_keys, external_store_keys

    def run(self) -> CheckResult:
        config = Config.get()
        all_external_keys = []
        all_external_store_keys = []
        accounts = get_account_ids_in_scope()
        for account in accounts:
            for region in config.active_regions:
                keys = get_kms_keys(account, region)
                if keys:
                    external_keys, external_store_keys = self._format_external_keys(
                        keys, account, region
                    )
                    all_external_keys.extend(external_keys)
                    all_external_store_keys.extend(external_store_keys)
        if all_external_keys:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "The following KMS keys are of type EXTERNAL, which requires "
                    "human access to unencrypted key material during key "
                    "generation:\n"
                    + "\n".join(sorted(all_external_keys))
                    + "\n\nThese keys should be replaced with AWS_KMS or "
                    "AWS_CLOUDHSM keys to prevent human access to unencrypted "
                    "key material."
                ),
            )
        message_parts = []
        if all_external_store_keys:
            message_parts.extend(
                [
                    "The following KMS keys are in external key stores. Please verify "
                    "that appropriate controls are in place to prevent human access to "
                    "unencrypted key material:\n"
                    + "\n".join(sorted(all_external_store_keys))
                    + "\n\n"
                ]
            )
        message_parts.extend(
            [
                "Please verify that:\n"
                "- All data keys used by workloads are envelope encrypted with a key "
                "stored in a HSM-backed KMS\n"
                "- No human access to unencrypted data keys is possible\n"
                "- Data keys are only used in memory and never stored in unencrypted "
                "form"
            ]
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context="".join(message_parts),
        )
