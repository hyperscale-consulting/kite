"""Data collection module for Kite."""

from rich.console import Console
from dataclasses import asdict
from . import (
    organizations,
    ec2,
    ecs,
    eks,
    lambda_,
    rds,
    dynamodb,
    redshift,
    sagemaker,
    sns,
    sqs,
    s3,
    kms,
    cloudfront,
    iam,
    identity_center,
    identity_store,
    cognito,
    secretsmanager,
)
from kite.helpers import (
    assume_organizational_role,
    get_account_ids_in_scope,
    assume_role,
)
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
    save_ec2_instances,
    save_virtual_mfa_devices,
    save_password_policy,
    save_cognito_user_pools,
    save_cognito_user_pool,
    save_key_pairs,
    save_secrets,
    save_roles,
    save_inline_policy_document,
)
from kite.config import Config
from kite.models import WorkloadResources, WorkloadResource


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
        for instance in ec2.get_running_instances(session, region):
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
        for cluster in ecs.get_clusters(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="ECS",
                    resource_id=cluster.cluster_arn,
                    region=region,
                )
            )

        # Check EKS clusters
        for cluster in eks.get_clusters(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="EKS",
                    resource_id=cluster.cluster_name,
                    region=region,
                )
            )

        # Check Lambda functions
        for function in lambda_.get_functions(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="Lambda",
                    resource_id=function.function_name,
                    region=region,
                )
            )

        # Check RDS instances
        for instance in rds.get_instances(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="RDS",
                    resource_id=instance.instance_id,
                    region=region,
                    details={"engine": instance.engine},
                )
            )

        # Check DynamoDB tables
        for table in dynamodb.get_tables(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="DynamoDB",
                    resource_id=table.table_name,
                    region=region,
                )
            )

        # Check Redshift clusters
        for cluster in redshift.get_clusters(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="Redshift",
                    resource_id=cluster.cluster_id,
                    region=region,
                )
            )

        # Check SageMaker notebook instances
        for notebook in sagemaker.get_notebook_instances(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="SageMaker",
                    resource_id=notebook.notebook_name,
                    region=region,
                )
            )

        # Check SNS topics
        for topic in sns.get_topics(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="SNS",
                    resource_id=topic.topic_arn,
                    region=region,
                )
            )

        # Check SQS queues
        for queue in sqs.get_queues(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="SQS",
                    resource_id=queue.queue_url,
                    region=region,
                )
            )

        # Check KMS keys
        for key in kms.get_customer_keys(session, region):
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
    for bucket in s3.get_buckets(session):
        workload_resources.resources.append(
            WorkloadResource(
                resource_type="S3",
                resource_id=bucket.bucket_name,
            )
        )

    # Check CloudFront distributions
    for dist in cloudfront.get_distributions(session):
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
                report = iam.fetch_credentials_report(session)
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
                summary = iam.fetch_account_summary(session)
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
        instances = identity_center.list_identity_center_instances(session)

        for instance in instances:
            instance["HasIdentityStoreUsers"] = identity_store.has_users(
                session, instance["IdentityStoreId"]
            )

        save_identity_center_instances(instances)
        console.print(f"  [green]✓ Saved {len(instances)} Identity Center instances[/]")

        console.print("[bold green]✓ Completed gathering Identity Center instances[/]")

    except Exception as e:
        raise Exception(f"Error gathering Identity Center instances: {str(e)}")


def collect_ec2_instances() -> None:
    """
    Collect EC2 instances for all in-scope accounts and save them locally.

    This function collects EC2 instance information from all accounts in scope and
    saves it to the .kite/audit directory for later use by the audit checks.
    """
    try:
        console.print("\n[bold blue]Gathering EC2 instances...[/]")

        # Get all account IDs in scope
        account_ids = get_account_ids_in_scope()

        # Collect EC2 instances for each account
        for account_id in account_ids:
            try:
                console.print(
                    f"  [yellow]Fetching EC2 instances for account {account_id}...[/]"
                )
                session = assume_role(account_id)
                instances = []

                # Check EC2 instances in each region
                for region in Config.get().active_regions:
                    try:
                        # Get instances using the EC2 module
                        instances.extend(ec2.get_running_instances(session, region))
                    except Exception as e:
                        console.print(
                            f"    [red]✗ Error fetching EC2 instances in region "
                            f"{region}: {str(e)}[/]"
                        )
                        continue

                # Save the instances for this account
                save_ec2_instances(account_id, instances)
                console.print(
                    f"  [green]✓ Saved {len(instances)} EC2 instances for account "
                    f"{account_id}[/]"
                )

            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching EC2 instances for account "
                    f"{account_id}: {str(e)}[/]"
                )

        console.print("[bold green]✓ Completed gathering EC2 instances[/]")

    except Exception as e:
        raise Exception(f"Error gathering EC2 instances: {str(e)}")


def collect_virtual_mfa_devices() -> None:
    """
    Collect virtual MFA devices for all in-scope accounts and save them locally.
    """
    console.print("\n[bold blue]Gathering virtual MFA devices...[/]")

    for account_id in get_account_ids_in_scope():
        # Get virtual MFA devices
        session = assume_role(account_id)
        mfa_devices = iam.fetch_virtual_mfa_devices(session)
        save_virtual_mfa_devices(account_id, mfa_devices)

    console.print("[bold green]✓ Completed gathering virtual MFA devices[/]")


def collect_password_policies() -> None:
    """
    Collect password policies for all in-scope accounts and save them locally.
    """
    console.print("\n[bold blue]Gathering password policies...[/]")
    for account_id in get_account_ids_in_scope():
        # Get password policy
        session = assume_role(account_id)
        policy = iam.get_password_policy(session)
        save_password_policy(account_id, policy)

    console.print("[bold green]✓ Completed gathering password policies[/]")


def collect_cognito_user_pools() -> None:
    """
    Collect Cognito user pools for all accounts in scope.
    """
    account_ids = get_account_ids_in_scope()
    console.print("\n[bold blue]Gathering Cognito user pools...[/]")

    for account_id in account_ids:
        try:
            # Assume role in the account
            session = assume_role(account_id)

            # Get user pools
            console.print(
                f"  [yellow]Fetching Cognito user pools for account {account_id}...[/]"
            )
            user_pools = cognito.list_user_pools(session)

            # Save user pools
            save_cognito_user_pools(account_id, user_pools)

            # Get and save detailed info for each user pool
            for pool in user_pools:
                pool_id = pool["Id"]
                console.print(
                    f"  [yellow]Fetching details for user pool {pool_id}...[/]"
                )
                pool_data = cognito.fetch_cognito_user_pool(session, pool_id)
                save_cognito_user_pool(account_id, pool_id, pool_data)

            console.print(
                f"  [green]✓ Saved Cognito user pools for account {account_id}[/]"
            )
        except Exception as e:
            console.print(
                f"  [red]✗ Error fetching Cognito user pools for account "
                f"{account_id}: {str(e)}[/]"
            )


def collect_key_pairs() -> None:
    """
    Collect EC2 key pairs for all in-scope accounts and save them locally.
    """
    console.print("\n[bold blue]Gathering EC2 key pairs...[/]")

    for account_id in get_account_ids_in_scope():
        try:
            # Assume role in the account
            session = assume_role(account_id)

            # Get EC2 key pairs
            console.print(
                f"  [yellow]Fetching EC2 key pairs for account {account_id}...[/]"
            )
            key_pairs = ec2.get_key_pairs(session)

            # Save key pairs
            save_key_pairs(account_id, key_pairs)

            console.print(
                f"  [green]✓ Saved {len(key_pairs)} EC2 key pairs for account "
                f"{account_id}[/]"
            )
        except Exception as e:
            console.print(
                f"  [red]✗ Error fetching EC2 key pairs for account "
                f"{account_id}: {str(e)}[/]"
            )

    console.print("[bold green]✓ Completed gathering EC2 key pairs[/]")


def collect_secrets() -> None:
    """
    Collect Secrets Manager secrets for all in-scope accounts and save them locally.
    """
    console.print("\n[bold blue]Gathering Secrets Manager secrets...[/]")

    # Get all account IDs in scope
    account_ids = get_account_ids_in_scope()

    # Collect secrets for each account
    for account_id in account_ids:
        try:
            # Assume role in the account
            session = assume_role(account_id)

            # Check secrets in each active region
            for region in Config.get().active_regions:
                try:
                    console.print(
                        f"  [yellow]Fetching secrets for account {account_id} "
                        f"in region {region}...[/]"
                    )
                    secrets = secretsmanager.fetch_secrets(session, region)

                    # Convert dataclass objects to dictionaries for JSON serialization
                    secrets_dicts = [asdict(secret) for secret in secrets]

                    # Save secrets for this region
                    save_secrets(account_id, region, secrets_dicts)

                    console.print(
                        f"  [green]✓ Saved {len(secrets)} secrets for account "
                        f"{account_id} in region {region}[/]"
                    )
                except Exception as e:
                    console.print(
                        f"  [red]✗ Error fetching secrets for account {account_id} "
                        f"in region {region}: {str(e)}[/]"
                    )
        except Exception as e:
            console.print(
                f"  [red]✗ Error assuming role for account {account_id}: {str(e)}[/]"
            )

    console.print("[bold green]✓ Completed gathering Secrets Manager secrets[/]")


def collect_roles() -> None:
    """
    Collect IAM roles for all in-scope accounts and save them locally.
    Includes attached policies and inline policy names for each role.
    Stores inline policy documents separately.
    """
    console.print("\n[bold blue]Gathering IAM roles with policies...[/]")

    for account_id in get_account_ids_in_scope():
        try:
            # Assume role in the account
            session = assume_role(account_id)

            # Get IAM roles (includes attached and inline policy names)
            console.print(
                f"  [yellow]Fetching IAM roles with policies for "
                f"account {account_id}...[/]"
            )
            roles = iam.list_roles(session)

            # Count policies for summary
            total_attached_policies = sum(
                len(role.get("AttachedPolicies", [])) for role in roles
            )
            total_inline_policies = sum(
                len(role.get("InlinePolicyNames", [])) for role in roles
            )

            # Save roles
            save_roles(account_id, roles)

            # Collect and save inline policy documents separately
            console.print(
                f"  [yellow]Fetching inline policy documents for "
                f"account {account_id}...[/]"
            )
            policy_count = 0

            for role in roles:
                role_name = role["RoleName"]
                for policy_name in role.get("InlinePolicyNames", []):
                    try:
                        policy_doc = iam.get_role_inline_policy_document(
                            session, role_name, policy_name
                        )
                        save_inline_policy_document(
                            account_id,
                            role_name,
                            policy_name,
                            policy_doc["PolicyDocument"]
                        )
                        policy_count += 1
                    except Exception as e:
                        console.print(
                            f"  [red]✗ Error fetching policy document "
                            f"for role {role_name}, policy {policy_name}: {str(e)}[/]"
                        )

            console.print(
                f"  [green]✓ Saved {len(roles)} IAM roles with "
                f"{total_attached_policies} attached policies and "
                f"{total_inline_policies} inline policies for "
                f"account {account_id}[/]"
            )
            console.print(
                f"  [green]✓ Saved {policy_count} inline policy documents "
                f"for account {account_id}[/]"
            )
        except Exception as e:
            console.print(
                f"  [red]✗ Error fetching IAM roles for account "
                f"{account_id}: {str(e)}[/]"
            )

    console.print("[bold green]✓ Completed gathering IAM roles with policies[/]")


def collect_data() -> None:
    console.print("\n[bold blue]Gathering AWS data...[/]")
    collect_organization_data()
    collect_mgmt_account_workload_resources()
    collect_credentials_reports()
    collect_virtual_mfa_devices()
    collect_account_summaries()
    collect_identity_providers()
    collect_identity_center_instances()
    collect_ec2_instances()
    collect_password_policies()
    collect_cognito_user_pools()
    collect_key_pairs()
    collect_secrets()
    collect_roles()
    console.print("\n[bold green]✓ Data collection complete![/]")
