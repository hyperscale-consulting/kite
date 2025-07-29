from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_access_analyzers
from hyperscale.kite.helpers import get_account_ids_in_scope


class ActiveExternalAccessAnalyzerCheck:
    def __init__(self):
        self.check_id = "active-external-access-analyzer"
        self.check_name = "Active External Access Analyzer"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an active external access analyzer "
            "across all accounts. Either an active organization-wide external access "
            "analyzer, or active account-level external access analyzers in all "
            "accounts."
        )

    def _check_analyzer_configuration(self, analyzer):
        if analyzer.get("status") != "ACTIVE":
            return False
        return True

    def _get_analyzer_summary(self, analyzers):
        org_analyzer = None
        account_analyzers = []
        accounts_with_analyzer = set()
        for analyzer in analyzers:
            if analyzer.get("type") == "ORGANIZATION":
                org_analyzer = analyzer
            elif analyzer.get("type") == "ACCOUNT":
                account_analyzers.append(analyzer)
                accounts_with_analyzer.add(analyzer.get("arn", "").split(":")[4])
        all_accounts = set(get_account_ids_in_scope())
        accounts_without_analyzer = all_accounts - accounts_with_analyzer
        return {
            "has_org_analyzer": org_analyzer is not None,
            "org_analyzer": org_analyzer,
            "account_analyzers": account_analyzers,
            "accounts_with_analyzer": list(accounts_with_analyzer),
            "accounts_without_analyzer": list(accounts_without_analyzer),
        }

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        all_analyzers = []
        for account_id in account_ids:
            analyzers = get_access_analyzers(account_id)
            all_analyzers.extend(analyzers)
        summary = self._get_analyzer_summary(all_analyzers)
        if not summary["has_org_analyzer"] and not summary["account_analyzers"]:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="No external-access access analyzers found.",
                details={},
            )
        if summary["has_org_analyzer"]:
            org_analyzer = summary["org_analyzer"]
            if self._check_analyzer_configuration(org_analyzer):
                return CheckResult(
                    status=CheckStatus.PASS,
                    reason="Found an active organization-wide external access "
                    "analyzer.",
                    details={"summary": summary},
                )
        if summary["account_analyzers"]:
            if not summary["accounts_without_analyzer"]:
                all_valid = all(
                    self._check_analyzer_configuration(analyzer)
                    for analyzer in summary["account_analyzers"]
                )
                if all_valid:
                    return CheckResult(
                        status=CheckStatus.PASS,
                        reason="Found active account-level external access analyzers "
                        "in all accounts.",
                        details={"summary": summary},
                    )
        return CheckResult(
            status=CheckStatus.FAIL,
            reason="No active external access analyzer found.",
            details={"summary": summary},
        )
