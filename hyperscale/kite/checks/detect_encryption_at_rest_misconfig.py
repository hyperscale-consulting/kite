from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.utils import print_config_compliance_for_rules

encryption_rule_names = [
    "api-gw-cache-enabled-and-encrypted",
    "api-gw-cache-encrypted",
    "appsync-cache-ct-encryption-at-rest",
    "appsync-cache-encryption-at-rest",
    "athena-workgroup-encrypted-at-rest",
    "backup-recovery-point-encrypted",
    "cloud-trail-encryption-enabled",
    "cloudwatch-log-group-encrypted",
    "codebuild-project-artifact-encryption",
    "codebuild-project-s3-logs-encrypted",
    "codebuild-report-group-encrypted-at-rest",
    "dax-encryption-enabled",
    "dax-tls-endpoint-encryption",
    "docdb-cluster-encrypted",
    "dynamodb-table-encrypted-kms",
    "dynamodb-table-encryption-enabled",
    "ec2-ebs-encryption-by-default",
    "ec2-spot-fleet-request-ct-encryption-at-rest",
    "ecr-repository-cmk-encryption-enabled",
    "efs-encrypted-check",
    "efs-filesystem-ct-encrypted",
    "eks-cluster-secrets-encrypted",
    "eks-secrets-encrypted",
    "elasticache-repl-grp-encrypted-at-rest",
    "elasticsearch-encrypted-at-rest",
    "elasticsearch-node-to-node-encryption-check",
    "emr-security-configuration-encryption-rest",
    "encrypted-volumes",
    "event-data-store-cmk-encryption-enabled",
    "glue-ml-transform-encrypted-at-rest",
    "kinesis-firehose-delivery-stream-encrypted",
    "kinesis-stream-encrypted",
    "msk-connect-connector-encrypted",
    "neptune-cluster-encrypted",
    "neptune-cluster-snapshot-encrypted",
    "opensearch-encrypted-at-rest",
    "opensearch-node-to-node-encryption-check",
    "rds-cluster-encrypted-at-rest",
    "rds-proxy-tls-encryption",
    "rds-snapshot-encrypted",
    "rds-storage-encrypted",
    "redshift-serverless-namespace-cmk-encryption",
    "s3-bucket-server-side-encryption-enabled",
    "s3-default-encryption-kms",
    "sns-encrypted-kms",
    "sqs-queue-encrypted",
    "workspaces-root-volume-encryption-enabled",
    "workspaces-user-volume-encryption-enabled",
]


class DetectEncryptionAtRestMisconfigCheck:
    def __init__(self):
        self.check_id = "detect-encryption-at-rest-misconfig"
        self.check_name = "Detect Encryption at Rest Misconfigurations"

    @property
    def question(self) -> str:
        return (
            "Is AWS Config used to check that encryption at rest controls are "
            "enabled as required, alerting and automatically remediating where "
            "non-compliance is found?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that AWS Config rules are configured to detect and "
            "remediate encryption at rest misconfigurations for various AWS resources."
        )

    def run(self) -> CheckResult:
        message = "AWS Config Rules for Encryption at Rest:\n\n"
        message += print_config_compliance_for_rules(encryption_rule_names)
        message += (
            "Please review the above and consider:\n"
            "- Are Config rules configured to detect encryption at rest "
            "misconfigurations in each account and region?\n"
            "- Are alerts configured for non-compliant resources?\n"
            "- Is auto-remediation configured where appropriate?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
