from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_acm_pca_certificate_authorities
from hyperscale.kite.helpers import get_account_ids_in_scope


class ProtectRootCaCheck:
    def __init__(self):
        self.check_id = "protect-root-ca"
        self.check_name = "Protect Root CA"

    @property
    def question(self) -> str:
        return (
            "Is the root CA properly protected with minimal usage, intermediate CAs "
            "for day-to-day operations, and kept in a dedicated AWS account?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that the root CA is properly protected, its use is "
            "minimized, intermediate CAs are used for day-to-day operations, and the "
            "root CA is kept in its own dedicated AWS account."
        )

    def _get_certificate_authorities(self) -> list[dict]:
        seen_arns = set()
        unique_authorities = []
        account_ids = get_account_ids_in_scope()
        for account_id in account_ids:
            for region in Config.get().active_regions:
                authorities = get_acm_pca_certificate_authorities(account_id, region)
                for authority in authorities:
                    arn = authority.get("Arn")
                    if arn and arn not in seen_arns:
                        seen_arns.add(arn)
                        unique_authorities.append(authority)
        return unique_authorities

    def run(self) -> CheckResult:
        authorities = self._get_certificate_authorities()
        if authorities:
            message = "Private Certificate Authorities found:\n"
            for authority in authorities:
                message += (
                    f"- ARN: {authority.get('Arn')}\n"
                    f"  Type: {authority.get('Type')}\n"
                    f"  Status: {authority.get('Status')}\n"
                    f"  Owner Account: {authority.get('OwnerAccount')}\n\n"
                )
        else:
            message = "No private certificate authorities found.\n\n"
        message += (
            "Consider the following factors:\n"
            "- Is the use of the root CA minimized to only essential operations?\n"
            "- Are intermediate CAs used for day-to-day certificate operations?\n"
            "- Is the root CA kept in its own dedicated AWS account?\n"
            "- Is access to the root CA strictly controlled and monitored?\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
