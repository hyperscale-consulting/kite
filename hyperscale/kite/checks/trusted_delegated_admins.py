from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_delegated_admins
from hyperscale.kite.data import get_organization
from hyperscale.kite.organizations import DelegatedAdmin


class TrustedDelegatedAdminsCheck:
    def __init__(self):
        self.check_id = "trusted-delegated-admins"
        self.check_name = "Trusted Delegated Admins"

    @property
    def question(self) -> str:
        return "Are all delegated administrators trusted accounts?"

    @property
    def description(self) -> str:
        return (
            "Accounts that are delegated administrators for a service have permission "
            "to perform actions on behalf of the organization, so should be locked "
            "down accordingly. This check verifies that all delegated admins "
            "are trusted and restricted-access accounts."
        )

    def run(self) -> CheckResult:
        if not get_organization():
            return CheckResult(
                status=CheckStatus.PASS,
                reason="AWS Organization is not enabled.",
            )

        delegated_admins = get_delegated_admins()
        if not delegated_admins:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No delegated admins found.",
            )

        services_by_admin: dict[str, list[str]] = {}
        for admin in delegated_admins:
            if admin.id not in services_by_admin:
                services_by_admin[admin.id] = []
            services_by_admin[admin.id].append(admin.service_principal)

        all_admins: dict[str, DelegatedAdmin] = {}
        for admin in delegated_admins:
            if admin.id not in all_admins:
                all_admins[admin.id] = admin

        admin_list = []
        message = "Delegated Administrators:\n\n"
        for admin_id, admin in all_admins.items():
            services = services_by_admin[admin_id]
            admin_list.append(
                {
                    "id": admin_id,
                    "name": admin.name,
                    "email": admin.email,
                    "services": services,
                }
            )
            message += f"Account: {admin.name} ({admin.id})\n"
            message += f"Email: {admin.email}\n"
            message += "Services:\n"
            for service in services:
                message += f"  - {service}\n"
            message += "\n"
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
