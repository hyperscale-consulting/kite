import concurrent.futures
from collections.abc import Callable

from boto3 import Session
from botocore.exceptions import ClientError
from rich.console import Console

from hyperscale.kite.config import Config
from hyperscale.kite.data import save_access_analyzers
from hyperscale.kite.data import save_account_summary
from hyperscale.kite.data import save_acm_certificates
from hyperscale.kite.data import save_acm_pca_certificate_authorities
from hyperscale.kite.data import save_apigateway_rest_apis
from hyperscale.kite.data import save_appsync_graphql_apis
from hyperscale.kite.data import save_backup_protected_resources
from hyperscale.kite.data import save_backup_vaults
from hyperscale.kite.data import save_bucket_metadata
from hyperscale.kite.data import save_cloudfront_distributions
from hyperscale.kite.data import save_cloudfront_origin_access_identities
from hyperscale.kite.data import save_cloudfront_waf_logging_configurations
from hyperscale.kite.data import save_cloudfront_web_acls
from hyperscale.kite.data import save_cloudtrail_trails
from hyperscale.kite.data import save_cognito_user_pools
from hyperscale.kite.data import save_config_compliance_by_rule
from hyperscale.kite.data import save_config_delivery_channels
from hyperscale.kite.data import save_config_recorders
from hyperscale.kite.data import save_config_rules
from hyperscale.kite.data import save_credentials_report
from hyperscale.kite.data import save_custom_key_stores
from hyperscale.kite.data import save_customer_managed_policies
from hyperscale.kite.data import save_delegated_admins
from hyperscale.kite.data import save_detective_graphs
from hyperscale.kite.data import save_dynamodb_tables
from hyperscale.kite.data import save_ec2_instances
from hyperscale.kite.data import save_ecs_clusters
from hyperscale.kite.data import save_efs_file_systems
from hyperscale.kite.data import save_eks_clusters
from hyperscale.kite.data import save_elbv2_load_balancers
from hyperscale.kite.data import save_export_tasks
from hyperscale.kite.data import save_flow_logs
from hyperscale.kite.data import save_guardduty_detectors
from hyperscale.kite.data import save_iam_groups
from hyperscale.kite.data import save_iam_users
from hyperscale.kite.data import save_identity_center_instances
from hyperscale.kite.data import save_inspector2_configuration
from hyperscale.kite.data import save_inspector2_coverage
from hyperscale.kite.data import save_key_pairs
from hyperscale.kite.data import save_kms_keys
from hyperscale.kite.data import save_lambda_functions
from hyperscale.kite.data import save_log_groups
from hyperscale.kite.data import save_maintenance_windows
from hyperscale.kite.data import save_nacls
from hyperscale.kite.data import save_networkfirewall_firewalls
from hyperscale.kite.data import save_oidc_providers
from hyperscale.kite.data import save_organization
from hyperscale.kite.data import save_organization_features
from hyperscale.kite.data import save_password_policy
from hyperscale.kite.data import save_rds_instances
from hyperscale.kite.data import save_redshift_clusters
from hyperscale.kite.data import save_regional_waf_logging_configurations
from hyperscale.kite.data import save_regional_web_acls
from hyperscale.kite.data import save_roles
from hyperscale.kite.data import save_route53resolver_firewall_domain_lists
from hyperscale.kite.data import save_route53resolver_firewall_rule_group_associations
from hyperscale.kite.data import save_route53resolver_firewall_rule_groups
from hyperscale.kite.data import save_route53resolver_query_log_config_associations
from hyperscale.kite.data import save_route53resolver_query_log_configs
from hyperscale.kite.data import save_rtbs
from hyperscale.kite.data import save_sagemaker_notebook_instances
from hyperscale.kite.data import save_saml_providers
from hyperscale.kite.data import save_secrets
from hyperscale.kite.data import save_security_groups
from hyperscale.kite.data import save_securityhub_action_targets
from hyperscale.kite.data import save_securityhub_automation_rules
from hyperscale.kite.data import save_sns_topics
from hyperscale.kite.data import save_sqs_queues
from hyperscale.kite.data import save_subnets
from hyperscale.kite.data import save_virtual_mfa_devices
from hyperscale.kite.data import save_vpc_endpoints
from hyperscale.kite.data import save_vpc_peering_connections
from hyperscale.kite.data import save_vpcs
from hyperscale.kite.helpers import assume_role
from hyperscale.kite.helpers import get_account_ids_in_scope

from . import accessanalyzer
from . import acm
from . import acm_pca
from . import apigateway
from . import appsync
from . import backup
from . import cloudfront
from . import cloudtrail
from . import cognito
from . import configservice
from . import detective
from . import dynamodb
from . import ec2
from . import ecs
from . import efs
from . import eks
from . import elbv2
from . import guardduty
from . import iam
from . import identity_center
from . import inspector2
from . import kms
from . import lambda_
from . import logs
from . import networkfirewall
from . import organizations
from . import rds
from . import redshift
from . import route53resolver
from . import s3
from . import sagemaker
from . import secretsmanager
from . import securityhub
from . import sns
from . import sqs
from . import ssm
from . import wafv2

console = Console()


def _get_regional_web_acls(session: Session, region: str) -> list[dict]:
    return wafv2.get_web_acls(session, wafv2.Scope.REGIONAL.value, region)


def _get_regional_waf_logging_config(session: Session, region: str) -> list[dict]:
    return wafv2.get_logging_configurations(session, wafv2.Scope.REGIONAL.value, region)


def _get_cloudfront_web_acls(session: Session) -> list[dict]:
    return wafv2.get_web_acls(session, wafv2.Scope.CLOUDFRONT.value, "us-east-1")


def _get_cloudfront_waf_logging_config(session: Session) -> list[dict]:
    return wafv2.get_logging_configurations(
        session, wafv2.Scope.CLOUDFRONT.value, "us-east-1"
    )


class Collector:
    def __init__(
        self,
        session: Session,
        account_id: str,
        resource_type: str,
        fetch_fn: Callable,
        save_fn: Callable,
        region: str | None = None,
    ):
        self.session = session
        self.account_id = account_id
        self.resource_type = resource_type
        self.fetch_fn = fetch_fn
        self.save_fn = save_fn
        self.region = region

    def __call__(self):
        console.print(
            f"  [yellow]Fetching {self.resource_type} for account {self.account_id}"
            f"{f' in region {self.region}' if self.region else ''}...[/]"
        )
        resources = []
        try:
            if self.region:
                resources = self.fetch_fn(self.session, self.region)
            else:
                resources = self.fetch_fn(self.session)
        except ClientError as e:
            console.print(
                f"    [red]✗ Error fetching {self.resource_type}"
                f"{f' in region {self.region}' if self.region else ''}: {str(e)}[/]"
            )

        if self.region:
            self.save_fn(self.account_id, self.region, resources)
        else:
            self.save_fn(self.account_id, resources)

        try:
            n = len(resources)
        except TypeError:
            n = 1
        console.print(
            f"  [green]✓ Saved {n} {self.resource_type} for account "
            f"{self.account_id}"
            f"{f' in region {self.region}' if self.region else ''}[/]"
        )


_regional_collector_config = [
    ("EC2", ec2.get_running_instances, save_ec2_instances),
    ("Secrets", secretsmanager.fetch_secrets, save_secrets),
    ("KMS Keys", kms.get_keys, save_kms_keys),
    ("Custom Key Stores", kms.get_custom_key_stores, save_custom_key_stores),
    ("Lambda Functions", lambda_.get_functions, save_lambda_functions),
    ("SQS Queues", sqs.get_queues, save_sqs_queues),
    ("SNS Topics", sns.get_topics, save_sns_topics),
    ("Config Rules", configservice.fetch_rules, save_config_rules),
    (
        "Config Delivery Channels",
        configservice.fetch_delivery_channels,
        save_config_delivery_channels,
    ),
    ("Config Recorders", configservice.fetch_recorders, save_config_recorders),
    (
        "Config Compliance by Rule",
        configservice.fetch_compliance_by_rule,
        save_config_compliance_by_rule,
    ),
    ("VPC Endpoints", ec2.get_vpc_endpoints, save_vpc_endpoints),
    ("CloudTrail Trails", cloudtrail.get_trails, save_cloudtrail_trails),
    ("Flow Logs", ec2.get_flow_logs, save_flow_logs),
    ("VPCs", ec2.get_vpcs, save_vpcs),
    (
        "Route 53 Resolver Query Log Configs",
        route53resolver.get_query_log_configs,
        save_route53resolver_query_log_configs,
    ),
    (
        "Route 53 Resolver Query Log Config Associations",
        route53resolver.get_resolver_query_log_config_associations,
        save_route53resolver_query_log_config_associations,
    ),
    ("Log Groups", logs.get_log_groups, save_log_groups),
    ("Export Tasks", logs.get_export_tasks, save_export_tasks),
    ("ELBv2 Load Balancers", elbv2.get_load_balancers, save_elbv2_load_balancers),
    ("EKS Clusters", eks.get_clusters, save_eks_clusters),
    ("ECS Clusters", ecs.get_clusters, save_ecs_clusters),
    ("Detective Graphs", detective.get_graphs, save_detective_graphs),
    (
        "Security Hub Action Targets",
        securityhub.get_action_targets,
        save_securityhub_action_targets,
    ),
    (
        "Security Hub Automation Rules",
        securityhub.get_automation_rules,
        save_securityhub_automation_rules,
    ),
    ("DynamoDB Tables", dynamodb.get_tables, save_dynamodb_tables),
    ("GuardDuty Detectors", guardduty.get_detectors, save_guardduty_detectors),
    ("Backup Vaults", backup.get_backup_vaults, save_backup_vaults),
    (
        "Backup Protected Resources",
        backup.get_protected_resources,
        save_backup_protected_resources,
    ),
    ("ACM Certificates", acm.get_certificates, save_acm_certificates),
    (
        "ACM PCA Certificate Authorities",
        acm_pca.get_certificate_authorities,
        save_acm_pca_certificate_authorities,
    ),
    (
        "Inspector2 Configuration",
        inspector2.get_configuration,
        save_inspector2_configuration,
    ),
    ("Inspector2 Coverage", inspector2.get_coverage, save_inspector2_coverage),
    ("Maintenance Windows", ssm.get_maintenance_windows, save_maintenance_windows),
    ("RDS Instances", rds.get_instances, save_rds_instances),
    ("Subnets", ec2.get_subnets, save_subnets),
    ("EFS File Systems", efs.get_file_systems, save_efs_file_systems),
    ("Route Tables", ec2.get_rtbs, save_rtbs),
    ("Network ACLs", ec2.get_nacls, save_nacls),
    ("Security Groups", ec2.get_security_groups, save_security_groups),
    (
        "VPC Peering Connections",
        ec2.get_vpc_peering_connections,
        save_vpc_peering_connections,
    ),
    (
        "Route 53 Resolver Firewall Rule Groups",
        route53resolver.get_firewall_rule_groups,
        save_route53resolver_firewall_rule_groups,
    ),
    (
        "Route 53 Resolver Firewall Rule Group Associations",
        route53resolver.get_firewall_rule_group_associations,
        save_route53resolver_firewall_rule_group_associations,
    ),
    (
        "Route 53 Resolver Firewall Domain Lists",
        route53resolver.get_firewall_domain_lists,
        save_route53resolver_firewall_domain_lists,
    ),
    ("API Gateway REST APIs", apigateway.get_rest_apis, save_apigateway_rest_apis),
    ("AppSync GraphQL APIs", appsync.get_graphql_apis, save_appsync_graphql_apis),
    (
        "Network Firewalls",
        networkfirewall.get_firewalls,
        save_networkfirewall_firewalls,
    ),
    ("Regional Web ACLs", _get_regional_web_acls, save_regional_web_acls),
    (
        "Regional WAF Logging Configurations",
        _get_regional_waf_logging_config,
        save_regional_waf_logging_configurations,
    ),
    ("Cognito User Pools", cognito.get_user_pools, save_cognito_user_pools),
    ("Redshift Clusters", redshift.get_clusters, save_redshift_clusters),
    (
        "SageMaker Notebook Instances",
        sagemaker.get_notebook_instances,
        save_sagemaker_notebook_instances,
    ),
]

_global_collector_config = [
    ("IAM Users", iam.list_users, save_iam_users),
    ("IAM Groups", iam.list_groups, save_iam_groups),
    ("IAM Roles", iam.get_roles, save_roles),
    (
        "IAM Customer Managed Policies",
        iam.get_customer_managed_policies,
        save_customer_managed_policies,
    ),
    ("SAML Providers", iam.list_saml_providers, save_saml_providers),
    ("OIDC Providers", iam.list_oidc_providers, save_oidc_providers),
    ("CloudFront Web ACLs", _get_cloudfront_web_acls, save_cloudfront_web_acls),
    (
        "CloudFront WAF Logging Configurations",
        _get_cloudfront_waf_logging_config,
        save_cloudfront_waf_logging_configurations,
    ),
    ("Credentials Report", iam.fetch_credentials_report, save_credentials_report),
    ("Account Summary", iam.fetch_account_summary, save_account_summary),
    ("Virtual MFA Devices", iam.fetch_virtual_mfa_devices, save_virtual_mfa_devices),
    ("Password Policy", iam.get_password_policy, save_password_policy),
    ("EC2 Key Pairs", ec2.get_key_pairs, save_key_pairs),
    ("Access Analyzer Analyzers", accessanalyzer.list_analyzers, save_access_analyzers),
    (
        "CloudFront Origin Access Identities",
        cloudfront.get_origin_access_identities,
        save_cloudfront_origin_access_identities,
    ),
    (
        "CloudFront Distributions",
        cloudfront.get_distributions,
        save_cloudfront_distributions,
    ),
    ("S3 Buckets", s3.get_buckets, save_bucket_metadata),
    (
        "Identity Center Instances",
        identity_center.get_identity_center_instances,
        save_identity_center_instances,
    ),
]

_mgmt_account_collector_config = [
    ("Delegated Admins", organizations.fetch_delegated_admins, save_delegated_admins),
    (
        "Organization Features",
        iam.fetch_organization_features,
        save_organization_features,
    ),
]


class CollectException(Exception):
    pass


def collect_data() -> None:
    console.print("[bold blue]Gathering AWS data...[/]")

    collectors = []

    config = Config.get()
    if config.management_account_id:
        try:
            session = assume_role(config.management_account_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                raise CollectException(
                    f"Unable to assume role {config.role_name} in management account "
                    f"({config.management_account_id}). Please review IAM policies and "
                    "check that permission is granted to assume the role, "
                    "that the external ID matches, and that the assessment end date is "
                    "not in the past."
                ) from None
            raise
        console.print(
            "  [yellow]Fetching Organization data using account "
            f"{config.management_account_id}...[/]"
        )
        try:
            organization = organizations.fetch_organization(session)
            save_organization(config.management_account_id, organization)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ["AWSOrganizationsNotInUseException"]:
                raise CollectException(
                    "You configured a management account ID, but that account does not "
                    "belong to an AWS Organization."
                ) from e
            if error_code == "AccessDeniedException":
                raise CollectException(
                    "The account you have configured as the management account does "
                    "not have permission to access the AWS Organizations API - please "
                    "check that it is the organizations management account and not a "
                    "member account."
                ) from e
            raise

        console.print(
            f"  [green]✓ Saved Organization for account {config.management_account_id}"
        )

        for resource_type, fetch_fn, save_fn in _mgmt_account_collector_config:
            collectors.append(
                Collector(
                    session,
                    config.management_account_id,
                    resource_type,
                    fetch_fn,
                    save_fn,
                )
            )

    account_ids = get_account_ids_in_scope()
    for account_id in account_ids:
        session = assume_role(account_id)
        for resource_type, fetch_fn, save_fn in _global_collector_config:
            collectors.append(
                Collector(session, account_id, resource_type, fetch_fn, save_fn)
            )

        for region in Config.get().active_regions:
            for resource_type, fetch_fn, save_fn in _regional_collector_config:
                collectors.append(
                    Collector(
                        session,
                        account_id,
                        resource_type,
                        fetch_fn,
                        save_fn,
                        region,
                    )
                )

    console.print("\n[bold blue]Gathering account data in parallel...[/]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {}
        for collector in collectors:
            future = executor.submit(collector)
            futures[future] = collector

        errors = []
        for future in concurrent.futures.as_completed(futures):
            collector = futures[future]
            try:
                future.result()
            except Exception as e:
                errors.append(
                    f"  [red]✗ Error collecting {collector.resource_type} data for "
                    f"account {collector.account_id}"
                    f"{f' in region {collector.region}' if collector.region else ''}: "
                    f"{str(e)}[/]"
                )

        if errors:
            console.print("\n[bold red]Errors occurred during data collection:[/]")
            for error in errors:
                console.print(error)

    console.print("\n[bold green]✓ Data collection complete![/]")
