from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class DeployLogAnalysisToolsInAuditAccountCheck:
    def __init__(self):
        self.check_id = "deploy-log-analysis-tools-in-audit-account"
        self.check_name = "Deploy Log Analysis Tools in Audit Account"

    @property
    def question(self) -> str:
        return "Are log analysis tools deployed in the audit/security tooling account?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that log analysis tools (e.g., Athena, OpenSearch, "
            "etc.) are deployed in the audit/security tooling account and are properly "
            "configured to ingest logs from the log archive account."
        )

    def _find_audit_account(self, org) -> str | None:
        for account in org.get_accounts():
            if account.name.lower() in ["audit", "security tooling"]:
                return account.id
        return None

    def run(self) -> CheckResult:
        org = get_organization()
        if not org:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="No AWS Organization found. This check requires an "
                "organization.",
            )
        audit_account_id = self._find_audit_account(org)
        if audit_account_id:
            message = (
                f"Found audit/security tooling account with ID: {audit_account_id}\n\n"
                "Consider the following factors for log analysis tools:\n"
                "- Are log analysis tools (e.g., Athena, OpenSearch, etc.) "
                "deployed in this account?\n"
                "- Are the tools properly configured to ingest logs from the log "
                "archive account?"
            )
        else:
            message = (
                "No account named 'Audit' or 'Security Tooling' was found in the "
                "organization.\n\n"
                "Consider the following factors for log analysis tools:\n"
                "- Are log analysis tools (e.g., Athena, OpenSearch, etc.) "
                "deployed in a dedicated security tooling account?\n"
                "- Are the tools properly configured to ingest logs from the log "
                "archive account?"
            )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
