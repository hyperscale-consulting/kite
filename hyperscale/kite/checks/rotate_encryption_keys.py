from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_kms_keys
from hyperscale.kite.helpers import get_account_ids_in_scope


class RotateEncryptionKeysCheck:
    def __init__(self):
        self.check_id = "rotate-encryption-keys"
        self.check_name = "Rotate Encryption Keys"

    @property
    def question(self) -> str:
        return "Are all encryption keys rotated in line with defined crypto periods?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that all encryption keys are rotated in line with "
            "defined crypto periods."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        all_enabled_keys = []
        all_disabled_keys = []

        accounts = get_account_ids_in_scope()

        for account in accounts:
            for region in config.active_regions:
                keys = get_kms_keys(account, region)

                if keys:
                    enabled_keys, disabled_keys = self._format_keys_by_rotation_status(
                        keys, account, region
                    )
                    all_enabled_keys.extend(enabled_keys)
                    all_disabled_keys.extend(disabled_keys)

        message_parts = []

        if all_enabled_keys:
            message_parts.extend(
                [
                    "KMS keys with rotation enabled:\n"
                    + "\n".join(sorted(all_enabled_keys))
                    + "\n\n"
                ]
            )

        if all_disabled_keys:
            message_parts.extend(
                [
                    "KMS keys with rotation disabled:\n"
                    + "\n".join(sorted(all_disabled_keys))
                    + "\n\n"
                ]
            )

        message_parts.extend(
            [
                "Please verify that:\n"
                "- All keys are rotated according to defined crypto periods\n"
                "- Rotation periods align with security requirements\n"
                "- Rotation is automated where possible\n"
                "- Consider any envelope encrypted data keys used by workloads."
            ]
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context="".join(message_parts),
        )

    def _format_keys_by_rotation_status(
        self, keys: list[dict], account: str, region: str
    ) -> tuple[list[str], list[str]]:
        enabled_keys = []
        disabled_keys = []

        for key in keys:
            key_id = key.get("KeyId")
            if not key_id:
                continue

            metadata = key.get("Metadata", {})
            if metadata.get("KeyManager") != "CUSTOMER":
                continue

            formatted_key = f"  - {key_id} ({account}/{region})"
            rotation_status = key.get("RotationStatus", {})
            if rotation_status.get("RotationEnabled"):
                enabled_keys.append(formatted_key)
            else:
                disabled_keys.append(formatted_key)

        return enabled_keys, disabled_keys
