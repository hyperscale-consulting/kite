"""Data collection module for Kite."""

from rich.console import Console
from kite.organizations import (
    fetch_organization,
    fetch_delegated_admins,
)
from kite.iam import (
    fetch_organization_features,
    fetch_credentials_report,
    fetch_account_summary,
    list_saml_providers,
    list_oidc_providers,
)
from kite.helpers import assume_organizational_role, get_account_ids_in_scope
from kite.data import (
    save_organization,
    save_delegated_admins,
    save_mgmt_account_workload_resources,
    save_organization_features,
    save_credentials_report,
    save_account_summary,
    save_saml_providers,
    save_oidc_providers,
    save_identity_center_instances,
)
from kite.config import Config
from kite.helpers import assume_role
from kite.models import WorkloadResources, WorkloadResource
from kite.ec2 import get_running_instances
from kite.ecs import get_clusters as get_ecs_clusters
from kite.eks import get_clusters as get_eks_clusters
from kite.lambda_ import get_functions
from kite.rds import get_instances as get_rds_instances
from kite.dynamodb import get_tables
from kite.redshift import get_clusters as get_redshift_clusters
from kite.sagemaker import get_notebook_instances
from kite.sns import get_topics
from kite.sqs import get_queues
from kite.s3 import get_buckets
from kite.kms import get_customer_keys
from kite.cloudfront import get_distributions
from kite.identity_center import list_identity_center_instances

console = Console()


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
        org = fetch_organization(session)

        save_organization(org)
        console.print("  [green]✓ Saved organization data[/]")

        # Collect delegated admin data
        console.print("  [yellow]Fetching delegated admins...[/]")
        admins = fetch_delegated_admins(session)
        save_delegated_admins(admins)
        console.print("  [green]✓ Saved delegated admins[/]")

        # Collect organization features
        console.print("  [yellow]Fetching organization features...[/]")
        features = fetch_organization_features(session)
        save_organization_features(features)
        console.print("  [green]✓ Saved organization features[/]")

        console.print("[bold green]✓ Completed gathering organization data[/]")

    except Exception as e:
        raise Exception(f"Error gathering organization data: {str(e)}")


def collect_mgmt_account_workload_resources() -> None:
    """
    Collect workload resources from the management account.

    """
    config = Config.get()
    mgmt_account_id = config.management_account_id
    if not mgmt_account_id:
        return

    console.print("\n[bold blue]Gathering management account workload data...[/]")

    # Assume role in the management account
    session = assume_role(account_id=mgmt_account_id)

    # Initialize workload resources collection
    workload_resources = WorkloadResources()

    # Check resources in each active region
    for region in config.active_regions:
        console.print(f"  [yellow]Scanning resources in {region}...[/]")
        # Check EC2 instances
        for instance in get_running_instances(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="EC2",
                    resource_id=instance.instance_id,
                    region=region,
                    details={
                        "instance_type": instance.instance_type,
                        "state": instance.state,
                    },
                )
            )

        # Check ECS clusters
        for cluster in get_ecs_clusters(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="ECS",
                    resource_id=cluster.cluster_arn,
                    region=region,
                )
            )

        # Check EKS clusters
        for cluster in get_eks_clusters(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="EKS",
                    resource_id=cluster.cluster_name,
                    region=region,
                )
            )

        # Check Lambda functions
        for function in get_functions(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="Lambda",
                    resource_id=function.function_name,
                    region=region,
                )
            )

        # Check RDS instances
        for instance in get_rds_instances(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="RDS",
                    resource_id=instance.instance_id,
                    region=region,
                    details={"engine": instance.engine},
                )
            )

        # Check DynamoDB tables
        for table in get_tables(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="DynamoDB",
                    resource_id=table.table_name,
                    region=region,
                )
            )

        # Check Redshift clusters
        for cluster in get_redshift_clusters(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="Redshift",
                    resource_id=cluster.cluster_id,
                    region=region,
                )
            )

        # Check SageMaker notebook instances
        for notebook in get_notebook_instances(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="SageMaker",
                    resource_id=notebook.notebook_name,
                    region=region,
                )
            )

        # Check SNS topics
        for topic in get_topics(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="SNS",
                    resource_id=topic.topic_arn,
                    region=region,
                )
            )

        # Check SQS queues
        for queue in get_queues(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="SQS",
                    resource_id=queue.queue_url,
                    region=region,
                )
            )

        # Check KMS keys
        for key in get_customer_keys(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="KMS",
                    resource_id=key.key_id,
                    region=region,
                    details={"description": key.description},
                )
            )

        console.print(f"  [green]✓ Finished scanning resources in {region}[/]")

    console.print("  [yellow]Scanning global resources...[/]")
    # Check global resources (not region-specific)
    # Check S3 buckets
    for bucket in get_buckets(session):
        workload_resources.resources.append(
            WorkloadResource(
                resource_type="S3",
                resource_id=bucket.bucket_name,
            )
        )

    # Check CloudFront distributions
    for dist in get_distributions(session):
        workload_resources.resources.append(
            WorkloadResource(
                resource_type="CloudFront",
                resource_id=dist.distribution_id,
                details={"domain_name": dist.domain_name},
            )
        )

    # Save the collected resources
    save_mgmt_account_workload_resources(workload_resources)
    console.print("  [green]✓ Saved management account workload data[/]")
    console.print("[bold green]✓ Completed gathering workload data[/]")


def collect_credentials_reports() -> None:
    """
    Collect IAM credentials reports for all in-scope accounts and save them locally.

    This function collects credentials reports from all accounts in scope and saves them
    to the .kite/audit directory for later use by the audit checks.
    """
    try:
        console.print("\n[bold blue]Gathering IAM credentials reports...[/]")

        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()

        # Collect credentials report for each account
        for account_id in account_ids:
            try:
                console.print(
                    f"  [yellow]Fetching credentials report for account "
                    f"{account_id}...[/]"
                )
                session = assume_role(account_id)
                report = fetch_credentials_report(session)
                save_credentials_report(account_id, report)
                console.print(
                    f"  [green]✓ Saved credentials report for account {account_id}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching credentials report for account "
                    f"{account_id}: {str(e)}[/]"
                )

        console.print("[bold green]✓ Completed gathering IAM credentials reports[/]")

    except Exception as e:
        raise Exception(f"Error gathering IAM credentials reports: {str(e)}")


def collect_account_summaries() -> None:
    """
    Collect IAM account summaries for all in-scope accounts and save them locally.

    This function collects account summaries from all accounts in scope and saves them
    to the .kite/audit directory for later use by the audit checks.
    """
    try:
        console.print("\n[bold blue]Gathering IAM account summaries...[/]")

        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()

        # Collect account summary for each account
        for account_id in account_ids:
            try:
                console.print(
                    f"  [yellow]Fetching account summary for account "
                    f"{account_id}...[/]"
                )
                session = assume_role(account_id)
                summary = fetch_account_summary(session)
                save_account_summary(account_id, summary)
                console.print(
                    f"  [green]✓ Saved account summary for account {account_id}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching account summary for account "
                    f"{account_id}: {str(e)}[/]"
                )

        console.print("[bold green]✓ Completed gathering IAM account summaries[/]")

    except Exception as e:
        raise Exception(f"Error gathering IAM account summaries: {str(e)}")


def collect_identity_providers() -> None:
    """
    Collect SAML and OIDC providers and save them locally.

    This function collects identity provider information and saves it
    to the .kite/audit directory for later use by the audit checks.
    """
    try:
        console.print("\n[bold blue]Gathering identity providers...[/]")

        # Assume role in the management account
        session = assume_organizational_role()

        # Collect SAML providers
        console.print("  [yellow]Fetching SAML providers...[/]")
        saml_providers = list_saml_providers(session)
        save_saml_providers(saml_providers)
        console.print("  [green]✓ Saved SAML providers[/]")

        # Collect OIDC providers
        console.print("  [yellow]Fetching OIDC providers...[/]")
        oidc_providers = list_oidc_providers(session)
        save_oidc_providers(oidc_providers)
        console.print("  [green]✓ Saved OIDC providers[/]")

        console.print("[bold green]✓ Completed gathering identity providers[/]")

    except Exception as e:
        raise Exception(f"Error gathering identity providers: {str(e)}")


def collect_identity_center_instances() -> None:
    """
    Collect Identity Center instances and save them locally.

    This function collects Identity Center instance information and saves it
    to the .kite/audit directory for later use by the audit checks.
    """
    try:
        console.print("\n[bold blue]Gathering Identity Center instances...[/]")

        # Assume role in the management account
        session = assume_organizational_role()

        # Collect Identity Center instances
        console.print("  [yellow]Fetching Identity Center instances...[/]")
        instances = list_identity_center_instances(session)
        save_identity_center_instances(instances)
        console.print(f"  [green]✓ Saved {len(instances)} Identity Center instances[/]")

        console.print("[bold green]✓ Completed gathering Identity Center instances[/]")

    except Exception as e:
        raise Exception(f"Error gathering Identity Center instances: {str(e)}")


def collect_data() -> None:
    console.print("\n[bold blue]Gathering AWS data...[/]")
    collect_organization_data()
    collect_mgmt_account_workload_resources()
    collect_credentials_reports()
    collect_account_summaries()
    collect_identity_providers()
    collect_identity_center_instances()
    console.print("\n[bold green]✓ Data collection complete![/]")
