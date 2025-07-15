import concurrent.futures
from typing import Callable
import logging

from botocore.exceptions import ClientError
from boto3 import Session
from rich.console import Console

from kite.config import Config
from kite.data import save_access_analyzers
from kite.data import save_account_summary
from kite.data import save_acm_certificates
from kite.data import save_acm_pca_certificate_authorities
from kite.data import save_apigateway_rest_apis
from kite.data import save_appsync_graphql_apis
from kite.data import save_backup_protected_resources
from kite.data import save_backup_vaults
from kite.data import save_bucket_metadata
from kite.data import save_cloudfront_distributions
from kite.data import save_cloudfront_origin_access_identities
from kite.data import save_cloudtrail_trails
from kite.data import save_cognito_user_pools
from kite.data import save_config_compliance_by_rule
from kite.data import save_config_delivery_channels
from kite.data import save_config_recorders
from kite.data import save_config_rules
from kite.data import save_credentials_report
from kite.data import save_custom_key_stores
from kite.data import save_customer_managed_policies
from kite.data import save_delegated_admins
from kite.data import save_detective_graphs
from kite.data import save_dynamodb_tables
from kite.data import save_ec2_instances
from kite.data import save_ecs_clusters
from kite.data import save_efs_file_systems
from kite.data import save_eks_clusters
from kite.data import save_elbv2_load_balancers
from kite.data import save_export_tasks
from kite.data import save_flow_logs
from kite.data import save_guardduty_detectors
from kite.data import save_iam_groups
from kite.data import save_iam_users
from kite.data import save_identity_center_instances
from kite.data import save_inspector2_configuration
from kite.data import save_inspector2_coverage
from kite.data import save_key_pairs
from kite.data import save_kms_keys
from kite.data import save_lambda_functions
from kite.data import save_log_groups
from kite.data import save_maintenance_windows
from kite.data import save_nacls
from kite.data import save_networkfirewall_firewalls
from kite.data import save_oidc_providers
from kite.data import save_organization
from kite.data import save_organization_features
from kite.data import save_password_policy
from kite.data import save_rds_instances
from kite.data import save_roles
from kite.data import save_route53resolver_firewall_domain_lists
from kite.data import save_route53resolver_firewall_rule_group_associations
from kite.data import save_route53resolver_firewall_rule_groups
from kite.data import save_route53resolver_query_log_config_associations
from kite.data import save_route53resolver_query_log_configs
from kite.data import save_rtbs
from kite.data import save_saml_providers
from kite.data import save_secrets
from kite.data import save_security_groups
from kite.data import save_securityhub_action_targets
from kite.data import save_securityhub_automation_rules
from kite.data import save_sns_topics
from kite.data import save_sqs_queues
from kite.data import save_subnets
from kite.data import save_virtual_mfa_devices
from kite.data import save_vpc_endpoints
from kite.data import save_vpc_peering_connections
from kite.data import save_vpcs
from kite.data import save_regional_web_acls
from kite.data import save_regional_waf_logging_configurations
from kite.data import save_cloudfront_web_acls
from kite.data import save_cloudfront_waf_logging_configurations
from kite.data import save_redshift_clusters
from kite.data import save_sagemaker_notebook_instances
from kite.helpers import assume_organizational_role
from kite.helpers import assume_role
from kite.helpers import get_account_ids_in_scope

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
logger = logging.getLogger(__name__)


def _make_collector(
    session: Session,
    account_id: str,
    resource_type: str,
    fetch_fn: Callable,
    save_fn: Callable,
    region: str | None = None,
):
    def collector():
        if region:
            _collect_regional_resources(
                region, session, account_id, resource_type, fetch_fn, save_fn
            )
        else:
            _collect_global_resources(
                session, account_id, resource_type, fetch_fn, save_fn
            )

    return collector


def _collect_regional_resources(
    region: str,
    session: Session,
    account_id: str,
    resource_type: str,
    fetch_fn: Callable,
    save_fn: Callable,
):
    console.print(
        f"  [yellow]Fetching {resource_type} for account {account_id} in region "
        f"{region}...[/]"
    )
    resources = []
    try:
        resources = fetch_fn(session, region)
    except ClientError as e:
        console.print(
            f"    [red]✗ Error fetching {resource_type} in region {region}: {str(e)}[/]"
        )

    save_fn(account_id, region, resources)
    console.print(
        f"  [green]✓ Saved {len(resources)} {resource_type} for account "
        f"{account_id} in region {region}[/]"
    )


def _collect_global_resources(
    session: Session,
    account_id: str,
    resource_type: str,
    fetch_fn: Callable,
    save_fn: Callable,
):
    console.print(f"  [yellow]Fetching {resource_type} for account {account_id}...[/]")
    resources = []
    try:
        resources = fetch_fn(session)
    except ClientError as e:
        console.print(f"    [red]✗ Error fetching {resource_type}: {str(e)}[/]")
    if resources is None:
        raise Exception(f"No {resource_type} found for account {account_id}")

    save_fn(account_id, resources)
    console.print(
        f"  [green]✓ Saved {len(resources)} {resource_type} for account {account_id}[/]"
    )


def collect_organization_data() -> None:
    """
    Collect organization data and save it locally.

    This function collects data about the AWS organization structure and saves it
    to the .kite/audit directory for later use by the audit checks.
    """
    try:
        console.print("\n[bold blue]Gathering organization data...[/]")

        # Assume role in the management account
        session = assume_organizational_role()

        # Get organization data
        console.print("  [yellow]Fetching organization details...[/]")
        org = organizations.fetch_organization(session)
        save_organization(org)
        console.print("  [green]✓ Saved organization data[/]")

        # Collect delegated admin data
        console.print("  [yellow]Fetching delegated admins...[/]")
        admins = organizations.fetch_delegated_admins(session)
        save_delegated_admins(admins)
        console.print("  [green]✓ Saved delegated admins[/]")

        # Collect organization features
        console.print("  [yellow]Fetching organization features...[/]")
        features = iam.fetch_organization_features(session)
        save_organization_features(features)
        console.print("  [green]✓ Saved organization features[/]")

        console.print("[bold green]✓ Completed gathering organization data[/]")

    except Exception as e:
        raise Exception(f"Error gathering organization data: {str(e)}")


def collect_identity_providers() -> None:
    """
    Collect SAML and OIDC providers and save them locally.
    """
    try:
        console.print("\n[bold blue]Gathering identity providers...[/]")

        # Assume role in the management account
        session = assume_organizational_role()

        # Collect SAML providers
        console.print("  [yellow]Fetching SAML providers...[/]")
        saml_providers = iam.list_saml_providers(session)
        save_saml_providers(saml_providers)
        console.print("  [green]✓ Saved SAML providers[/]")

        # Collect OIDC providers
        console.print("  [yellow]Fetching OIDC providers...[/]")
        oidc_providers = iam.list_oidc_providers(session)
        save_oidc_providers(oidc_providers)
        console.print("  [green]✓ Saved OIDC providers[/]")

        console.print("[bold green]✓ Completed gathering identity providers[/]")

    except Exception as e:
        raise Exception(f"Error gathering identity providers: {str(e)}")


# def collect_identity_center_instances() -> None:
#     """
#     Collect Identity Center instances and save them locally.
#     """
#     try:
#         console.print("\n[bold blue]Gathering Identity Center instances...[/]")

#         # Assume role in the management account
#         session = assume_organizational_role()

#         # Collect Identity Center instances
#         console.print("  [yellow]Fetching Identity Center instances...[/]")
#         instances = identity_center.get_identity_center_instances(session)

#         for instance in instances:
#             instance["HasIdentityStoreUsers"] = identity_store.has_users(
#                 session, instance["IdentityStoreId"]
#             )

#         save_identity_center_instances(instances)
#         console.print(f"  [green]✓ Saved {len(instances)} Identity Center instances[/]")

#         console.print("[bold green]✓ Completed gathering Identity Center instances[/]")

#     except Exception as e:
#         raise Exception(f"Error gathering Identity Center instances: {str(e)}")


# def collect_mgmt_account_workload_resources() -> None:
#     """
#     Collect workload resources from the management account.
#     """
#     config = Config.get()
#     mgmt_account_id = config.management_account_id
#     if not mgmt_account_id:
#         return

#     console.print("\n[bold blue]Gathering management account workload data...[/]")

#     # Assume role in the management account
#     session = assume_role(account_id=mgmt_account_id)

#     # Initialize workload resources collection
#     workload_resources = WorkloadResources()

#     # Check resources in each active region
#     for region in config.active_regions:
#         console.print(f"  [yellow]Scanning resources in {region}...[/]")
#         # Check EC2 instances
#         for instance in ec2.get_running_instances(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="EC2",
#                     resource_id=instance.get("InstanceId"),
#                     region=region,
#                     details={
#                         "instance_type": instance.get("InstanceType"),
#                         "state": instance.get("State", {}).get("Name"),
#                     },
#                 )
#             )

#         # Check ECS clusters
#         for cluster in ecs.get_clusters(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="ECS",
#                     resource_id=cluster["clusterArn"],
#                     region=region,
#                 )
#             )

#         # Check EKS clusters
#         for cluster in eks.get_cluster_names(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="EKS",
#                     resource_id=cluster.cluster,
#                     region=region,
#                 )
#             )

#         # Check Lambda functions
#         for function in lambda_.get_functions(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="Lambda",
#                     resource_id=function["FunctionName"],
#                     region=region,
#                 )
#             )

#         # Check RDS instances
#         for instance in rds.get_instances(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="RDS",
#                     resource_id=instance.get("DBInstanceIdentifier"),
#                     region=region,
#                     details={"engine": instance.get("Engine")},
#                 )
#             )

#         # Check DynamoDB tables
#         for table in dynamodb.get_tables(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="DynamoDB",
#                     resource_id=table["TableName"],
#                     region=region,
#                 )
#             )

#         # Check Redshift clusters
#         for cluster in redshift.get_clusters(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="Redshift",
#                     resource_id=cluster.cluster_id,
#                     region=region,
#                 )
#             )

#         # Check SageMaker notebook instances
#         for notebook in sagemaker.get_notebook_instances(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="SageMaker",
#                     resource_id=notebook.notebook_name,
#                     region=region,
#                 )
#             )

#         # Check SNS topics
#         for topic in sns.get_topics(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="SNS",
#                     resource_id=topic.topic_arn,
#                     region=region,
#                 )
#             )

#         # Check SQS queues
#         for queue in sqs.get_queues(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="SQS",
#                     resource_id=queue["queue_url"],
#                     region=region,
#                 )
#             )

#         # Check KMS keys
#         for key in kms.get_keys(session, region):
#             workload_resources.resources.append(
#                 WorkloadResource(
#                     resource_type="KMS",
#                     resource_id=key["KeyId"],
#                     region=region,
#                     details={"description": key["Description"]},
#                 )
#             )

#         console.print(f"  [green]✓ Finished scanning resources in {region}[/]")

#     console.print("  [yellow]Scanning global resources...[/]")
#     # Check global resources (not region-specific)
#     # Check S3 buckets
#     for bucket in s3.get_bucket_names(session):
#         workload_resources.resources.append(
#             WorkloadResource(
#                 resource_type="S3",
#                 resource_id=bucket,
#             )
#         )

#     # Check CloudFront distributions
#     for dist in cloudfront.get_distributions(session):
#         workload_resources.resources.append(
#             WorkloadResource(
#                 resource_type="CloudFront",
#                 resource_id=dist["Id"],
#                 details={"domain_name": dist["DomainName"]},
#             )
#         )

#     # Save the collected resources
#     save_mgmt_account_workload_resources(workload_resources)
#     console.print("  [green]✓ Saved management account workload data[/]")
#     console.print("[bold green]✓ Completed gathering workload data[/]")


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
        console.print(
            f"  [green]✓ Saved {len(resources)} {self.resource_type} for account "
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


def collect_data() -> None:
    """
    Collect all AWS data in parallel.
    """
    console.print("\n[bold blue]Gathering AWS data...[/]")

    # First collect organization-level data
    collect_organization_data()
    # collect_identity_providers()
    # collect_identity_center_instances()
    # collect_mgmt_account_workload_resources()

    # Get all account IDs in scope
    account_ids = get_account_ids_in_scope()

    collectors = []
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
