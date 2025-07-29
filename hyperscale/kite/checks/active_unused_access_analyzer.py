from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_access_analyzers
from hyperscale.kite.helpers import get_account_ids_in_scope


class ActiveUnusedAccessAnalyzerCheck:
    def __init__(self):
        self.check_id = "active-unused-access-analyzer"
        self.check_name = "Active Unused Access Analyzer"

    @property
    def question(self) -> str:
        return "Is there an active unused access analyzer across all accounts?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an active unused access analyzer "
            "across all accounts. Either an active organization-wide unused access "
            "analyzer with no exclusions and unused access age < 90 days, or active "
            "account-level unused access analyzers in all accounts with no exclusions "
            "and unused access age < 90 days."
        )

    def _check_analyzer_configuration(self, analyzer):
        if analyzer.get("type") not in [
            "ORGANIZATION_UNUSED_ACCESS",
            "ACCOUNT_UNUSED_ACCESS",
        ]:
            return False
        if analyzer.get("status") != "ACTIVE":
            return False
        config = analyzer.get("configuration", {})
        unused_access = config.get("unusedAccess", {})
        analysis_rule = unused_access.get("analysisRule", {})
        if analysis_rule.get("exclusions"):
            return False
        if unused_access.get("unusedAccessAge", 0) > 90:
            return False
        return True

    def _get_analyzer_summary(self, analyzers):
        org_analyzer = None
        account_analyzers = []
        accounts_with_analyzer = set()
        accounts_without_analyzer = set()
        for analyzer in analyzers:
            if analyzer.get("type") == "ORGANIZATION_UNUSED_ACCESS":
                org_analyzer = analyzer
            elif analyzer.get("type") == "ACCOUNT_UNUSED_ACCESS":
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
                reason="No unused-access access analyzers found.",
                details={},
            )
        if summary["has_org_analyzer"]:
            org_analyzer = summary["org_analyzer"]
            if self._check_analyzer_configuration(org_analyzer):
                return CheckResult(
                    status=CheckStatus.PASS,
                    reason=(
                        "Found an active organization-wide unused access analyzer "
                        "with no exclusions and unused access age < 90 days."
                    ),
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
                        reason=(
                            "Found active account-level unused access analyzers "
                            "in all accounts with no exclusions and unused access "
                            "age < 90 days."
                        ),
                        details={"summary": summary},
                    )
        message = (
            "Consider the following:\n"
            "- Is there an active organization-wide unused access analyzer with no "
            "exclusions and unused access age < 90 days?\n"
            "- Or are there active account-level unused access analyzers in all "
            "accounts with no exclusions and unused access age < 90 days?\n\n"
            f"Current status:\n"
            "- Organization-wide analyzer: "
            f"{'Yes' if summary['has_org_analyzer'] else 'No'}\n"
            "- Accounts with analyzers: "
            f"{len(summary['accounts_with_analyzer'])}\n"
            "- Accounts without analyzers: "
            f"{len(summary['accounts_without_analyzer'])}\n"
        )
        if summary["has_org_analyzer"]:
            message += (
                "\nOrganization-wide analyzer configuration:\n"
                f"{summary['org_analyzer']}\n"
            )
        if summary["account_analyzers"]:
            message += (
                f"\nAccount-level analyzers found in "
                f"{len(summary['accounts_with_analyzer'])} accounts.\n"
            )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
            details={"summary": summary},
        )
