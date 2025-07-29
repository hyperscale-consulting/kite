from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_kms_keys
from hyperscale.kite.helpers import get_account_ids_in_scope


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
        all_hsm_keys = []
        all_external_store_keys = []

        # Get all in-scope accounts
        accounts = get_account_ids_in_scope()

        # Check each account in each active region
        for account in accounts:
            for region in config.active_regions:
                # Get keys for this account and region
                keys = get_kms_keys(account, region)

                if keys:
                    hsm_keys, external_store_keys = self._format_keys_by_origin(
                        keys, account, region
                    )
                    all_hsm_keys.extend(hsm_keys)
                    all_external_store_keys.extend(external_store_keys)

        # Format the output
        output = []
        if all_hsm_keys:
            output.append("\nAWS KMS keys protected by hardware security module:")
            output.extend(sorted(all_hsm_keys))

        if all_external_store_keys:
            output.append(
                "\nExternal key store keys (please verify these are protected by "
                "hardware security module):"
            )
            output.extend(sorted(all_external_store_keys))

        # Build the message
        message = (
            "All keys should be stored in a KMS using HSMs to protect keys. This "
            "includes keys used by workloads to encrypt data, which should be envelope "
            "encrypted with a key that is stored in a HSM-backed KMS.\n\n"
            "Current KMS Keys:\n" + "\n".join(output) + "\n\nPlease verify that:\n"
            "- All keys used for data encryption are envelope encrypted with a key "
            "stored in a HSM-backed KMS\n"
            "- All external key stores use hardware security modules to protect keys"
        )

        return CheckResult(status=CheckStatus.MANUAL, context=message)

    def _format_keys_by_origin(
        self, keys: list[dict], account: str, region: str
    ) -> tuple[list[str], list[str]]:
        """
        Format KMS keys grouped by their origin.

        Args:
            keys: List of KMS key dictionaries
            account: AWS account ID
            region: AWS region

        Returns:
            Tuple of (hsm_keys, external_store_keys) where each is a list of
            formatted key strings
        """
        # Group keys by origin
        hsm_keys = []
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
            if origin in ["AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM"]:
                hsm_keys.append(formatted_key)
            elif origin == "EXTERNAL_KEY_STORE":
                external_store_keys.append(formatted_key)

        return hsm_keys, external_store_keys
