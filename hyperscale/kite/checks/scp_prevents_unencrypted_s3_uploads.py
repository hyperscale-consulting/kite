import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class ScpPreventsUnencryptedS3UploadsCheck:
    def __init__(self):
        self.check_id = "scp-prevents-unencrypted-s3-uploads"
        self.check_name = "SCP Prevents Unencrypted S3 Uploads"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an SCP that prevents unencrypted "
            "S3 uploads."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so SCP preventing "
                    "unencrypted S3 uploads cannot be assessed."
                ),
            )

        # Check root OU for S3 encryption deny SCP
        root_scps = org.root.scps
        root_has_s3_deny = False
        root_s3_deny_scp = None

        for scp in root_scps:
            try:
                content = json.loads(scp.content)
                if self._is_s3_encryption_deny_scp(content):
                    root_has_s3_deny = True
                    root_s3_deny_scp = scp
                    break
            except json.JSONDecodeError:
                continue

        # If root has S3 encryption deny SCP, we're good
        if root_has_s3_deny and root_s3_deny_scp is not None:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "SCP preventing unencrypted S3 uploads is attached to the root OU."
                ),
                details={
                    "scp": {
                        "id": root_s3_deny_scp.id,
                        "name": root_s3_deny_scp.name,
                        "arn": root_s3_deny_scp.arn,
                    },
                },
            )

        # Check top-level OUs for S3 encryption deny SCP
        top_level_ous = org.root.child_ous
        ous_without_s3_deny = []
        ous_with_s3_deny = []

        # If there's no S3 encryption deny SCP on root and no top-level OUs,
        # that's a fail
        if not top_level_ous:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "SCP preventing unencrypted S3 uploads is not attached to the "
                    "root OU and there are no top-level OUs."
                ),
            )

        for ou in top_level_ous:
            ou_has_s3_deny = False
            for scp in ou.scps:
                try:
                    content = json.loads(scp.content)
                    if self._is_s3_encryption_deny_scp(content):
                        ou_has_s3_deny = True
                        ous_with_s3_deny.append(
                            {
                                "ou_name": ou.name,
                                "scp": {
                                    "id": scp.id,
                                    "name": scp.name,
                                    "arn": scp.arn,
                                },
                            }
                        )
                        break
                except json.JSONDecodeError:
                    continue

            if not ou_has_s3_deny:
                ous_without_s3_deny.append(ou.name)

        if ous_without_s3_deny:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "SCP preventing unencrypted S3 uploads is not attached to the "
                    "root OU or all top-level OUs. The following top-level OUs "
                    "do not have an S3 encryption deny SCP: "
                )
                + ", ".join(ous_without_s3_deny),
            )

        return CheckResult(
            status=CheckStatus.PASS,
            reason=(
                "SCP preventing unencrypted S3 uploads is attached to all "
                "top-level OUs."
            ),
            details={
                "scps_by_ou": ous_with_s3_deny,
            },
        )

    def _is_s3_encryption_deny_scp(self, content: dict) -> bool:
        if not isinstance(content, dict) or "Statement" not in content:
            return False

        statements = content["Statement"]
        if not isinstance(statements, list):
            statements = [statements]

        required_actions = {"s3:PutObject"}

        required_condition = {
            "Null": {
                "s3:x-amz-server-side-encryption": "true",
            },
        }

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            # Check for a deny statement with the required S3 action and condition
            if (
                statement.get("Effect") == "Deny"
                and "Action" in statement
                and "Resource" in statement
                and statement["Resource"] == "*"
                and "Condition" in statement
                and statement["Condition"] == required_condition
            ):
                actions = statement["Action"]
                if not isinstance(actions, list):
                    actions = [actions]

                # Check if all required actions are present
                if all(action in actions for action in required_actions):
                    return True

        return False
