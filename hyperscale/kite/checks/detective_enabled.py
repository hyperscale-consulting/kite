from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_delegated_admins
from hyperscale.kite.data import get_detective_graphs
from hyperscale.kite.data import get_organization
from hyperscale.kite.helpers import get_account_ids_in_scope


class DetectiveEnabledCheck:
    def __init__(self):
        self.check_id = "detective-enabled"
        self.check_name = "AWS Detective Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that AWS Detective is enabled for all organization "
            "accounts (or all in-scope accounts if not in an organization), "
            "and that each account is a member with status 'ENABLED' in at least one "
            "Detective graph in each active region."
        )

    def _get_detective_delegated_admin(self, org) -> str:
        detective_principal = "detective.amazonaws.com"
        delegated_admins = get_delegated_admins()
        if delegated_admins:
            for admin in delegated_admins:
                if admin.service_principal == detective_principal:
                    return admin.id
        return org.master_account_id

    def _check_detective_membership(
        self, account_ids: set, region: str, admin_account: str
    ):
        missing_accounts = []
        disabled_accounts = []
        graphs = get_detective_graphs(admin_account, region)
        if not graphs:
            return list(account_ids), []
        members = {}
        for graph in graphs:
            for member in graph.get("Members", []):
                members[member["AccountId"]] = member["Status"]
        for account_id in account_ids:
            if account_id not in members:
                missing_accounts.append(account_id)
            elif members[account_id] != "ENABLED":
                disabled_accounts.append(account_id)
        return missing_accounts, disabled_accounts

    def run(self) -> CheckResult:
        account_ids = set(get_account_ids_in_scope())
        org = get_organization()
        missing_accounts = defaultdict(list)
        disabled_accounts = defaultdict(list)
        if not org:
            for region in Config.get().active_regions:
                for account_id in account_ids:
                    region_missing, region_disabled = self._check_detective_membership(
                        account_ids, region, account_id
                    )
                    if region_missing:
                        missing_accounts[region].extend(region_missing)
                    if region_disabled:
                        disabled_accounts[region].extend(region_disabled)
            if missing_accounts or disabled_accounts:
                message = "AWS Detective is not enabled for all in-scope accounts."
                if missing_accounts:
                    message += "\n\nMissing accounts:"
                    for region, accounts in missing_accounts.items():
                        message += f"\n{region}: {', '.join(accounts)}"
                if disabled_accounts:
                    message += "\n\nDisabled accounts:"
                    for region, accounts in disabled_accounts.items():
                        message += f"\n{region}: {', '.join(accounts)}"
                return CheckResult(
                    status=CheckStatus.FAIL,
                    reason="AWS Detective is not enabled for all in-scope accounts.",
                    details={
                        "missing_accounts": dict(missing_accounts),
                        "disabled_accounts": dict(disabled_accounts),
                        "message": message,
                    },
                )
            return CheckResult(
                status=CheckStatus.PASS,
                reason="AWS Detective is enabled for all in-scope accounts.",
                details={
                    "message": "AWS Detective is enabled for all in-scope accounts.",
                },
            )
        delegated_admin = self._get_detective_delegated_admin(org)
        for region in Config.get().active_regions:
            region_missing, region_disabled = self._check_detective_membership(
                account_ids, region, delegated_admin
            )
            if region_missing:
                missing_accounts[region].extend(region_missing)
            if region_disabled:
                disabled_accounts[region].extend(region_disabled)
        if missing_accounts or disabled_accounts:
            message = "AWS Detective is not enabled for all organization accounts."
            if missing_accounts:
                message += "\n\nMissing accounts:"
                for region, accounts in missing_accounts.items():
                    message += f"\n{region}: {', '.join(accounts)}"
            if disabled_accounts:
                message += "\n\nDisabled accounts:"
                for region, accounts in disabled_accounts.items():
                    message += f"\n{region}: {', '.join(accounts)}"
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="AWS Detective is not enabled for all organization accounts.",
                details={
                    "missing_accounts": dict(missing_accounts),
                    "disabled_accounts": dict(disabled_accounts),
                    "message": message,
                },
            )
        return CheckResult(
            status=CheckStatus.PASS,
            reason="AWS Detective is enabled for all organization accounts.",
            details={
                "message": "AWS Detective is enabled for all organization accounts.",
            },
        )
