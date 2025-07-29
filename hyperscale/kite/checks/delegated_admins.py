from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_delegated_admins
from hyperscale.kite.data import get_organization


class DelegatedAdminForSecurityServices:
    def __init__(self):
        self.check_id = "delegated-admin-for-security-services"
        self.check_name = "Delegated admin for security services"

    @property
    def question(self) -> str:
        return (
            "Is the delegated administrator account for security services the "
            "security tooling account?"
        )

    @property
    def description(self) -> str:
        return (
            "Delegated administrators is an AWS Organizations feature that allows you "
            "to delegate administration duties to a member account, reducing the need "
            "for access to the management account. This check verifies that the "
            "delegated administrator for AWS security services is the Security Tooling "
            "(AKA Audit) account."
        )

    def run(self) -> CheckResult:
        if get_organization() is None:
            return CheckResult(
                CheckStatus.PASS,
                "AWS Organization is not enabled so this check is not applicable.",
            )
        security_services = [
            "securityhub.amazonaws.com",
            "inspector2.amazonaws.com",
            "macie.amazonaws.com",
            "detective.amazonaws.com",
            "guardduty.amazonaws.com",
        ]

        delegated_admins = get_delegated_admins()
        if not delegated_admins:
            return CheckResult(
                CheckStatus.FAIL,
                "No delegated administrators found for any services.",
            )

        admins_by_service = {}
        for admin in delegated_admins:
            if admin.service_principal in security_services:
                admins_by_service[admin.service_principal] = admin

        # Check each security service
        missing_services = []
        security_service_admins = {}

        for service in security_services:
            if service in admins_by_service:
                security_service_admins[service] = admins_by_service[service]
            else:
                missing_services.append(service)

        if missing_services:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "The following security services do not have delegated "
                    f"administrators: {', '.join(missing_services)}"
                ),
            )

        admins_info = "Delegated Administrators for Security Services:\n"
        for service, admin in security_service_admins.items():
            admins_info += f"\n{service}: "
            admins_info += f"{admin.name} ({admin.id}) - {admin.email}\n"

        return CheckResult(status=CheckStatus.MANUAL, context=admins_info)
