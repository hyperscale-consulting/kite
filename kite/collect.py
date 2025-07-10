"""Data collection module for Kite."""

import concurrent.futures
import botocore
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
    accessanalyzer,
    configservice,
    cloudtrail,
    route53resolver,
    logs,
    wafv2,
    elbv2,
    detective,
    securityhub,
    guardduty,
    backup,
    acm,
    acm_pca,
    inspector2,
    ssm,
    efs,
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
    save_customer_managed_policies,
    save_policy_document,
    save_bucket_metadata,
    save_sns_topics,
    save_sqs_queues,
    save_lambda_functions,
    save_kms_keys,
    # save_identity_center_permission_sets,
    save_identity_store_users,
    save_identity_store_groups,
    save_access_analyzers,
    save_iam_users,
    save_iam_groups,
    save_config_rules,
    save_cloudfront_origin_access_identities,
    save_vpc_endpoints,
    save_cloudtrail_trails,
    save_flow_logs,
    save_vpcs,
    save_route53resolver_query_log_configs,
    save_route53resolver_query_log_config_associations,
    save_log_groups,
    save_export_tasks,
    save_wafv2_web_acls,
    save_wafv2_logging_configurations,
    save_elbv2_load_balancers,
    save_eks_clusters,
    save_config_recorders,
    save_config_delivery_channels,
    save_detective_graphs,
    save_securityhub_action_targets,
    save_securityhub_automation_rules,
    save_dynamodb_tables,
    save_custom_key_stores,
    save_config_compliance_by_rule,
    save_guardduty_detectors,
    save_backup_vaults,
    save_backup_protected_resources,
    save_acm_certificates,
    save_acm_pca_certificate_authorities,
    save_inspector2_configuration,
    save_inspector2_coverage,
    save_maintenance_windows,
    save_ecs_clusters,
    save_rds_instances,
    save_subnets,
    save_efs_file_systems,
    save_rtbs,
    save_nacls,
    save_security_groups,
    save_vpc_peering_connections,
    save_route53resolver_firewall_rule_groups,
    save_route53resolver_firewall_rule_group_associations,
    save_route53resolver_firewall_domain_lists,
)
from kite.config import Config
from kite.models import WorkloadResources, WorkloadResource


console = Console()


def collect_account_data(account_id: str) -> None:
    """
    Collect all data for a single account.

    Args:
        account_id: The AWS account ID to collect data from
    """
    try:
        # Assume role in the account once
        session = assume_role(account_id)

        # Collect credentials report
        console.print(
            f"  [yellow]Fetching credentials report for account {account_id}...[/]"
        )
        report = iam.fetch_credentials_report(session)
        save_credentials_report(account_id, report)
        console.print(
            f"  [green]✓ Saved credentials report for account {account_id}[/]"
        )

        # Collect account summary
        console.print(
            f"  [yellow]Fetching account summary for account {account_id}...[/]"
        )
        summary = iam.fetch_account_summary(session)
        save_account_summary(account_id, summary)
        console.print(f"  [green]✓ Saved account summary for account {account_id}[/]")

        # Collect virtual MFA devices
        console.print(
            f"  [yellow]Fetching virtual MFA devices for account {account_id}...[/]"
        )
        mfa_devices = iam.fetch_virtual_mfa_devices(session)
        save_virtual_mfa_devices(account_id, mfa_devices)
        console.print(
            f"  [green]✓ Saved virtual MFA devices for account {account_id}[/]"
        )

        # Collect password policy
        console.print(
            f"  [yellow]Fetching password policy for account {account_id}...[/]"
        )
        policy = iam.get_password_policy(session)
        save_password_policy(account_id, policy)
        console.print(f"  [green]✓ Saved password policy for account {account_id}[/]")

        # Collect Cognito user pools
        console.print(
            f"  [yellow]Fetching Cognito user pools for account {account_id}...[/]"
        )
        user_pools = cognito.list_user_pools(session)
        save_cognito_user_pools(account_id, user_pools)

        for pool in user_pools:
            pool_id = pool["Id"]
            pool_data = cognito.fetch_cognito_user_pool(session, pool_id)
            save_cognito_user_pool(account_id, pool_id, pool_data)
        console.print(
            f"  [green]✓ Saved Cognito user pools for account {account_id}[/]"
        )

        # Collect EC2 key pairs
        console.print(
            f"  [yellow]Fetching EC2 key pairs for account {account_id}...[/]"
        )
        key_pairs = ec2.get_key_pairs(session)
        save_key_pairs(account_id, key_pairs)
        console.print(
            f"  [green]✓ Saved {len(key_pairs)} EC2 key pairs for account {account_id}[/]"
        )

        # Collect EC2 instances
        console.print(
            f"  [yellow]Fetching EC2 instances for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching EC2 instances for account {account_id} in region {region}...[/]"
                )
                instances = ec2.get_running_instances(session, region)
                save_ec2_instances(account_id, region, instances)
                console.print(
                    f"  [green]✓ Saved {len(instances)} EC2 instances for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"    [red]✗ Error fetching EC2 instances in region {region}: {str(e)}[/]"
                )

        # Collect secrets
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching secrets for account {account_id} in region {region}...[/]"
                )
                secrets = secretsmanager.fetch_secrets(session, region)
                secrets_dicts = [asdict(secret) for secret in secrets]
                save_secrets(account_id, region, secrets_dicts)
                console.print(
                    f"  [green]✓ Saved {len(secrets)} secrets for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching secrets for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect IAM users and groups
        console.print(
            f"  [yellow]Fetching IAM users and groups for account {account_id}...[/]"
        )
        users = iam.list_users(session)
        save_iam_users(account_id, users)
        groups = iam.list_groups(session)
        save_iam_groups(account_id, groups)

        # Collect IAM roles and policies
        console.print(
            f"  [yellow]Fetching IAM roles with policies for account {account_id}...[/]"
        )
        roles = iam.list_roles(session)
        save_roles(account_id, roles)

        # Collect inline policy documents
        policy_count = 0
        for role in roles:
            role_name = role["RoleName"]
            for policy_name in role.get("InlinePolicyNames", []):
                try:
                    policy_doc = iam.get_role_inline_policy_document(
                        session, role_name, policy_name
                    )
                    save_inline_policy_document(
                        account_id, role_name, policy_name, policy_doc["PolicyDocument"]
                    )
                    policy_count += 1
                except Exception as e:
                    console.print(
                        f"  [red]✗ Error fetching policy document for role {role_name}, policy {policy_name}: {str(e)}[/]"
                    )

        # Collect customer managed policies
        policies = iam.list_customer_managed_policies(session)
        save_customer_managed_policies(account_id, policies)

        # Collect policy documents
        policy_document_count = 0
        for policy in policies:
            policy_arn = policy["Arn"]
            try:
                policy_info = iam.get_policy_and_document(session, policy_arn)
                save_policy_document(
                    account_id, policy_arn, policy_info["PolicyDocument"]
                )
                policy_document_count += 1
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching policy document for policy {policy['PolicyName']}: {str(e)}[/]"
                )

        console.print(
            f"  [green]✓ Saved {len(roles)} IAM roles with {policy_count} inline policies and "
            f"{len(policies)} customer managed policies with {policy_document_count} policy documents "
            f"for account {account_id}[/]"
        )

        # Collect S3 bucket policies
        console.print(
            f"  [yellow]Fetching S3 bucket metadata for account {account_id}...[/]"
        )
        buckets = s3.get_buckets(session)
        save_bucket_metadata(account_id, buckets)
        console.print(
            f"  [green]✓ Saved {len(buckets)} S3 bucket metadata for account {account_id}[/]"
        )

        # Collect SNS topics
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching SNS topics for account {account_id} in region {region}...[/]"
                )
                topics = sns.get_topics(session, region)
                topics_dicts = [
                    {
                        "topic_arn": topic.topic_arn,
                        "region": topic.region,
                        "policy": topic.policy,
                    }
                    for topic in topics
                ]
                save_sns_topics(account_id, region, topics_dicts)
                console.print(
                    f"  [green]✓ Saved {len(topics)} SNS topics for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching SNS topics for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect SQS queues
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching SQS queues for account {account_id} in region {region}...[/]"
                )
                queues = sqs.get_queues(session, region)
                save_sqs_queues(account_id, region, queues)
                console.print(
                    f"  [green]✓ Saved {len(queues)} SQS queues for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching SQS queues for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Lambda functions
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching Lambda functions for account {account_id} in region {region}...[/]"
                )
                functions = lambda_.get_functions(session, region)
                save_lambda_functions(account_id, region, functions)
                console.print(
                    f"  [green]✓ Saved {len(functions)} Lambda functions for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Lambda functions for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect KMS keys
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching KMS keys for account {account_id} in region {region}...[/]"
                )
                keys = kms.get_keys(session, region)
                save_kms_keys(account_id, region, keys)
                console.print(
                    f"  [green]✓ Saved {len(keys)} KMS keys for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching KMS keys for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect custom key stores
        console.print(
            f"  [yellow]Fetching custom key stores for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                custom_key_stores = kms.get_custom_key_stores(session, region)
                save_custom_key_stores(account_id, region, custom_key_stores)
                console.print(
                    f"  [green]✓ Saved {len(custom_key_stores)} custom key stores for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching custom key stores for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect account level identity center instances
        console.print(
            f"  [yellow]Fetching Identity Center instances for account {account_id}...[/]"
        )
        instances = identity_center.list_identity_center_instances(session)
        save_identity_center_instances(instances, account_id)
        console.print(
            f"  [green]✓ Saved {len(instances)} Identity Center instances for account {account_id}[/]"
        )

        # Collect account level identity store users
        console.print(
            f"  [yellow]Fetching Identity Store users for account {account_id}...[/]"
        )
        for instance in instances:
            users = identity_store.get_users(session, instance["IdentityStoreId"])
            save_identity_store_users(account_id, instance["IdentityStoreId"], users)
            console.print(
                f"  [green]✓ Saved {len(users)} Identity Store users for "
                f"account {account_id} and instance "
                f"{instance['IdentityStoreId']}[/]"
            )

        # Collect account level identity store groups
        console.print(
            f"  [yellow]Fetching Identity Store groups for account {account_id}...[/]"
        )
        for instance in instances:
            groups = identity_store.get_groups(session, instance["IdentityStoreId"])
            save_identity_store_groups(account_id, instance["IdentityStoreId"], groups)
            console.print(
                f"  [green]✓ Saved {len(groups)} Identity Store groups for "
                f"account {account_id} and instance "
                f"{instance['IdentityStoreId']}[/]"
            )

        # Collect account level identity center permission sets
        # TODO: This is not working - current permissions (SecurityAudit and
        # ViewOnlyAccess) do not allow
        # console.print(
        #    f"  [yellow]Fetching Identity Center permission sets for account {account_id}...[/]"
        # )
        # for instance in instances:
        #    permission_sets = identity_center.list_permission_sets(session, instance["InstanceArn"])
        #    save_identity_center_permission_sets(account_id, instance["IdentityStoreId"], permission_sets)
        #    console.print(f"  [green]✓ Saved {len(permission_sets)} Identity Center permission sets for "
        #                  f"account {account_id} and instance "
        #                  f"{instance['IdentityStoreId']}[/]")

        # Collect access analyzer analyzers
        console.print(
            f"  [yellow]Fetching Access Analyzer analyzers for account {account_id}...[/]"
        )
        analyzers = accessanalyzer.list_analyzers(session)
        save_access_analyzers(account_id, analyzers)
        console.print(
            f"  [green]✓ Saved {len(analyzers)} Access Analyzer analyzers for account {account_id}[/]"
        )

        # Collect Config recorders
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching Config recorders for account {account_id} in region {region}...[/]"
                )
                recorders = configservice.fetch_recorders(session, region)
                save_config_recorders(account_id, region, recorders)
                console.print(
                    f"  [green]✓ Saved {len(recorders)} Config recorders for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Config recorders for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Config delivery channels
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching Config delivery channels for account {account_id} in region {region}...[/]"
                )
                channels = configservice.fetch_delivery_channels(session, region)
                save_config_delivery_channels(account_id, region, channels)
                console.print(
                    f"  [green]✓ Saved {len(channels)} Config delivery channels for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Config delivery channels for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Config rules
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching Config rules for account {account_id} in region {region}...[/]"
                )
                rules = configservice.fetch_rules(session, region)
                save_config_rules(account_id, region, rules)
                console.print(
                    f"  [green]✓ Saved {len(rules)} Config rules for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Config rules for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Config compliance by rule
        for region in Config.get().active_regions:
            try:
                console.print(
                    f"  [yellow]Fetching Config compliance by rule for account {account_id} in region {region}...[/]"
                )
                compliance = configservice.fetch_compliance_by_rule(session, region)
                save_config_compliance_by_rule(account_id, region, compliance)
                console.print(
                    f"  [green]✓ Saved {len(compliance)} Config compliance by rule for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Config compliance by rule for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect CloudFront origin access identities
        console.print(
            f"  [yellow]Fetching CloudFront origin access identities for account {account_id}...[/]"
        )
        identities = cloudfront.get_origin_access_identities(session)
        save_cloudfront_origin_access_identities(account_id, identities)
        console.print(
            f"  [green]✓ Saved {len(identities)} CloudFront origin access identities for account {account_id}[/]"
        )

        # Collect VPC endpoints
        console.print(
            f"  [yellow]Fetching VPC endpoints for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                endpoints = ec2.get_vpc_endpoints(session, region)
                save_vpc_endpoints(account_id, region, endpoints)
                console.print(
                    f"  [green]✓ Saved {len(endpoints)} VPC endpoints for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching VPC endpoints for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect CloudTrail trails
        console.print(
            f"  [yellow]Fetching CloudTrail trails for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                trails = cloudtrail.get_trails(session, region)
                save_cloudtrail_trails(account_id, region, trails)
                console.print(
                    f"  [green]✓ Saved {len(trails)} CloudTrail trails for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching CloudTrail trails for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect flow logs
        console.print(f"  [yellow]Fetching flow logs for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                flow_logs = ec2.get_flow_logs(session, region)
                save_flow_logs(account_id, region, flow_logs)
                console.print(
                    f"  [green]✓ Saved {len(flow_logs)} flow logs for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching flow logs for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect VPCs
        console.print(f"  [yellow]Fetching VPCs for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                vpcs = ec2.get_vpcs(session, region)
                save_vpcs(account_id, region, vpcs)
                console.print(
                    f"  [green]✓ Saved {len(vpcs)} VPCs for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching VPCs for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Route 53 resolver query log configs

        console.print(
            f"  [yellow]Fetching Route 53 resolver query log configs for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                query_log_configs = route53resolver.get_query_log_configs(
                    session, region
                )
                save_route53resolver_query_log_configs(
                    account_id, region, query_log_configs
                )
                console.print(
                    f"  [green]✓ Saved {len(query_log_configs)} Route 53 resolver query log configs for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Route 53 resolver query log configs for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Route 53 resolver query log config associations

        console.print(
            f"  [yellow]Fetching Route 53 resolver query log config associations for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                resolver_query_log_config_associations = (
                    route53resolver.get_resolver_query_log_config_associations(
                        session, region
                    )
                )
                save_route53resolver_query_log_config_associations(
                    account_id, region, resolver_query_log_config_associations
                )
                console.print(
                    f"  [green]✓ Saved {len(resolver_query_log_config_associations)} Route 53 resolver query log config associations for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Route 53 resolver query log config associations for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect log groups

        console.print(f"  [yellow]Fetching log groups for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                log_groups = logs.get_log_groups(session, region)
                save_log_groups(account_id, region, log_groups)
                console.print(
                    f"  [green]✓ Saved {len(log_groups)} log groups for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching log groups for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect export tasks
        console.print(f"  [yellow]Fetching export tasks for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                export_tasks = logs.get_export_tasks(session, region)
                save_export_tasks(account_id, region, export_tasks)
                console.print(
                    f"  [green]✓ Saved {len(export_tasks)} export tasks for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching export tasks for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect WAFv2 web ACLs
        console.print(
            f"  [yellow]Fetching WAFv2 web ACLs for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                web_acls = wafv2.get_web_acls(
                    session, wafv2.Scope.REGIONAL.value, region
                )
                if region == "us-east-1":
                    web_acls.extend(
                        wafv2.get_web_acls(
                            session, wafv2.Scope.CLOUDFRONT.value, region
                        )
                    )
                save_wafv2_web_acls(account_id, region, web_acls)
                console.print(
                    f"  [green]✓ Saved {len(web_acls)} WAFv2 web ACLs for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching WAFv2 web ACLs for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect WAFv2 logging configurations
        console.print(
            f"  [yellow]Fetching WAFv2 logging configurations for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                logging_configurations = wafv2.get_logging_configurations(
                    session, wafv2.Scope.REGIONAL.value, region
                )
                if region == "us-east-1":
                    logging_configurations.extend(
                        wafv2.get_logging_configurations(
                            session, wafv2.Scope.CLOUDFRONT.value, region
                        )
                    )
                save_wafv2_logging_configurations(
                    account_id, region, logging_configurations
                )
                console.print(
                    f"  [green]✓ Saved {len(logging_configurations)} WAFv2 logging configurations for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching WAFv2 logging configurations for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect ELBv2 load balancers
        console.print(
            f"  [yellow]Fetching ELBv2 load balancers for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                load_balancers = elbv2.get_load_balancers(session, region)
                save_elbv2_load_balancers(account_id, region, load_balancers)
                console.print(
                    f"  [green]✓ Saved {len(load_balancers)} ELBv2 load balancers for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching ELBv2 load balancers for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect EKS clusters
        console.print(f"  [yellow]Fetching EKS clusters for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                clusters = eks.get_clusters(session, region)
                save_eks_clusters(account_id, region, clusters)
                console.print(
                    f"  [green]✓ Saved {len(clusters)} EKS clusters for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching EKS clusters for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect ECS clusters
        console.print(f"  [yellow]Fetching ECS clusters for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                clusters = ecs.get_clusters(session, region)
                save_ecs_clusters(account_id, region, clusters)
                console.print(
                    f"  [green]✓ Saved {len(clusters)} ECS clusters for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching ECS clusters for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect detective graphs
        console.print(
            f"  [yellow]Fetching detective graphs for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                graphs = detective.get_graphs(session, region)
                save_detective_graphs(account_id, region, graphs)
                console.print(
                    f"  [green]✓ Saved {len(graphs)} detective graphs for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching detective graphs for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect security hub action targets
        console.print(
            f"  [yellow]Fetching security hub action targets for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                action_targets = securityhub.get_action_targets(session, region)
                save_securityhub_action_targets(account_id, region, action_targets)
                console.print(
                    f"  [green]✓ Saved {len(action_targets)} security hub action targets for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching security hub action targets for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect security hub automation rules
        console.print(
            f"  [yellow]Fetching security hub automation rules for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                automation_rules = []
                try:
                    automation_rules = securityhub.get_automation_rules(session, region)
                except botocore.exceptions.ClientError as e:
                    if e.response["Error"]["Code"] != "AccessDeniedException":
                        raise e
                save_securityhub_automation_rules(account_id, region, automation_rules)
                console.print(
                    f"  [green]✓ Saved {len(automation_rules)} security hub automation rules for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching security hub automation rules for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect DynamoDB tables
        console.print(
            f"  [yellow]Fetching DynamoDB tables for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                tables = dynamodb.get_tables(session, region)
                save_dynamodb_tables(account_id, region, tables)
                console.print(
                    f"  [green]✓ Saved {len(tables)} DynamoDB tables for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching DynamoDB tables for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect GuardDuty detectors
        console.print(
            f"  [yellow]Fetching GuardDuty detectors for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                detectors = guardduty.get_detectors(session, region)
                save_guardduty_detectors(account_id, region, detectors)
                console.print(
                    f"  [green]✓ Saved {len(detectors)} GuardDuty detectors for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching GuardDuty detectors for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Backup vaults
        console.print(
            f"  [yellow]Fetching Backup vaults for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                vaults = backup.get_backup_vaults(session, region)
                save_backup_vaults(account_id, region, vaults)
                console.print(
                    f"  [green]✓ Saved {len(vaults)} Backup vaults for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Backup vaults for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Backup protected resources
        console.print(
            f"  [yellow]Fetching Backup protected resources for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                resources = backup.get_protected_resources(session, region)
                save_backup_protected_resources(account_id, region, resources)
                console.print(
                    f"  [green]✓ Saved {len(resources)} Backup protected resources for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Backup protected resources for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect ACM certificates
        console.print(
            f"  [yellow]Fetching ACM certificates for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                certificates = acm.get_certificates(session, region)
                save_acm_certificates(account_id, region, certificates)
                console.print(
                    f"  [green]✓ Saved {len(certificates)} ACM certificates for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching ACM certificates for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect ACM PCA certificate authorities
        console.print(
            f"  [yellow]Fetching ACM PCA certificate authorities for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                authorities = acm_pca.get_certificate_authorities(session, region)
                save_acm_pca_certificate_authorities(account_id, region, authorities)
                console.print(
                    f"  [green]✓ Saved {len(authorities)} ACM PCA certificate authorities for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching ACM PCA certificate authorities for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Inspector2 configuration
        console.print(
            f"  [yellow]Fetching Inspector2 configuration for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                configuration = inspector2.get_configuration(session, region)
                save_inspector2_configuration(account_id, region, configuration)
                console.print(
                    f"  [green]✓ Saved Inspector2 configuration for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Inspector2 configuration for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Inspector2 coverage
        console.print(
            f"  [yellow]Fetching Inspector2 coverage for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                coverage = inspector2.get_coverage(session, region)
                save_inspector2_coverage(account_id, region, coverage)
                console.print(
                    f"  [green]✓ Saved {len(coverage)} Inspector2 coverage for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Inspector2 coverage for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect maintenance windows
        console.print(
            f"  [yellow]Fetching maintenance windows for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                maintenance_windows = ssm.get_maintenance_windows(session, region)
                save_maintenance_windows(account_id, region, maintenance_windows)
                console.print(
                    f"  [green]✓ Saved {len(maintenance_windows)} maintenance windows for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching maintenance windows for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect RDS instances
        console.print(
            f"  [yellow]Fetching RDS instances for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                instances = rds.get_instances(session, region)
                save_rds_instances(account_id, region, instances)
                console.print(
                    f"  [green]✓ Saved {len(instances)} RDS instances for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching RDS instances for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect subnets
        console.print(f"  [yellow]Fetching subnets for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                subnets = ec2.get_subnets(session, region)
                save_subnets(account_id, region, subnets)
                console.print(
                    f"  [green]✓ Saved {len(subnets)} subnets for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching subnets for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect EFS file systems
        console.print(
            f"  [yellow]Fetching EFS file systems for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                file_systems = efs.get_file_systems(session, region)
                save_efs_file_systems(account_id, region, file_systems)
                console.print(
                    f"  [green]✓ Saved {len(file_systems)} EFS file systems for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching EFS file systems for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect route tables
        console.print(f"  [yellow]Fetching route tables for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                rtbs = ec2.get_rtbs(session, region)
                save_rtbs(account_id, region, rtbs)
                console.print(
                    f"  [green]✓ Saved {len(rtbs)} route tables for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching route tables for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect network ACLs
        console.print(f"  [yellow]Fetching network ACLs for account {account_id}...[/]")
        for region in Config.get().active_regions:
            try:
                nacls = ec2.get_nacls(session, region)
                save_nacls(account_id, region, nacls)
                console.print(
                    f"  [green]✓ Saved {len(nacls)} network ACLs for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching network ACLs for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect security groups
        console.print(
            f"  [yellow]Fetching security groups for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                security_groups = ec2.get_security_groups(session, region)
                save_security_groups(account_id, region, security_groups)
                console.print(
                    f"  [green]✓ Saved {len(security_groups)} security groups for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching security groups for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect VPC peering connections
        console.print(
            f"  [yellow]Fetching VPC peering connections for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                vpc_peering_connections = ec2.get_vpc_peering_connections(
                    session, region
                )
                save_vpc_peering_connections(
                    account_id, region, vpc_peering_connections
                )
                console.print(
                    f"  [green]✓ Saved {len(vpc_peering_connections)} VPC peering connections for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching VPC peering connections for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Route 53 Resolver firewall rule groups
        console.print(
            f"  [yellow]Fetching Route 53 Resolver firewall rule groups for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                firewall_rule_groups = route53resolver.get_firewall_rule_groups(
                    session, region
                )
                save_route53resolver_firewall_rule_groups(
                    account_id, region, firewall_rule_groups
                )
                console.print(
                    f"  [green]✓ Saved {len(firewall_rule_groups)} Route 53 Resolver firewall rule groups for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Route 53 Resolver firewall rule groups for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Route 53 Resolver firewall rule group associations
        console.print(
            f"  [yellow]Fetching Route 53 Resolver firewall rule group associations for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                firewall_rule_group_associations = (
                    route53resolver.get_firewall_rule_group_associations(
                        session, region
                    )
                )
                save_route53resolver_firewall_rule_group_associations(
                    account_id, region, firewall_rule_group_associations
                )
                console.print(
                    f"  [green]✓ Saved {len(firewall_rule_group_associations)} Route 53 Resolver firewall rule group associations for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Route 53 Resolver firewall rule group associations for account {account_id} in region {region}: {str(e)}[/]"
                )

        # Collect Route 53 Resolver firewall domain lists
        console.print(
            f"  [yellow]Fetching Route 53 Resolver firewall domain lists for account {account_id}...[/]"
        )
        for region in Config.get().active_regions:
            try:
                firewall_domain_lists = route53resolver.get_firewall_domain_lists(
                    session, region
                )
                save_route53resolver_firewall_domain_lists(
                    account_id, region, firewall_domain_lists
                )
                console.print(
                    f"  [green]✓ Saved {len(firewall_domain_lists)} Route 53 Resolver firewall domain lists for account {account_id} in region {region}[/]"
                )
            except Exception as e:
                console.print(
                    f"  [red]✗ Error fetching Route 53 Resolver firewall domain lists for account {account_id} in region {region}: {str(e)}[/]"
                )

    except Exception as e:
        console.print(
            f"  [red]✗ Error collecting data for account {account_id}: {str(e)}[/]"
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


def collect_identity_center_instances() -> None:
    """
    Collect Identity Center instances and save them locally.
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
                    resource_id=instance.get("InstanceId"),
                    region=region,
                    details={
                        "instance_type": instance.get("InstanceType"),
                        "state": instance.get("State", {}).get("Name"),
                    },
                )
            )

        # Check ECS clusters
        for cluster in ecs.get_clusters(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="ECS",
                    resource_id=cluster["clusterArn"],
                    region=region,
                )
            )

        # Check EKS clusters
        for cluster in eks.get_cluster_names(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="EKS",
                    resource_id=cluster.cluster,
                    region=region,
                )
            )

        # Check Lambda functions
        for function in lambda_.get_functions(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="Lambda",
                    resource_id=function["FunctionName"],
                    region=region,
                )
            )

        # Check RDS instances
        for instance in rds.get_instances(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="RDS",
                    resource_id=instance.get("DBInstanceIdentifier"),
                    region=region,
                    details={"engine": instance.get("Engine")},
                )
            )

        # Check DynamoDB tables
        for table in dynamodb.get_tables(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="DynamoDB",
                    resource_id=table["TableName"],
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
                    resource_id=queue["queue_url"],
                    region=region,
                )
            )

        # Check KMS keys
        for key in kms.get_keys(session, region):
            workload_resources.resources.append(
                WorkloadResource(
                    resource_type="KMS",
                    resource_id=key["KeyId"],
                    region=region,
                    details={"description": key["Description"]},
                )
            )

        console.print(f"  [green]✓ Finished scanning resources in {region}[/]")

    console.print("  [yellow]Scanning global resources...[/]")
    # Check global resources (not region-specific)
    # Check S3 buckets
    for bucket in s3.get_bucket_names(session):
        workload_resources.resources.append(
            WorkloadResource(
                resource_type="S3",
                resource_id=bucket,
            )
        )

    # Check CloudFront distributions
    for dist in cloudfront.get_distributions(session):
        workload_resources.resources.append(
            WorkloadResource(
                resource_type="CloudFront",
                resource_id=dist["Id"],
                details={"domain_name": dist["DomainName"]},
            )
        )

    # Save the collected resources
    save_mgmt_account_workload_resources(workload_resources)
    console.print("  [green]✓ Saved management account workload data[/]")
    console.print("[bold green]✓ Completed gathering workload data[/]")


def collect_data() -> None:
    """
    Collect all AWS data in parallel.
    """
    console.print("\n[bold blue]Gathering AWS data...[/]")

    # First collect organization-level data
    collect_organization_data()
    collect_identity_providers()
    collect_identity_center_instances()
    collect_mgmt_account_workload_resources()

    # Get all account IDs in scope
    account_ids = get_account_ids_in_scope()

    # Collect data for each account in parallel
    console.print("\n[bold blue]Gathering account data in parallel...[/]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        # Submit all account data collection tasks
        futures = {
            executor.submit(collect_account_data, account_id): account_id
            for account_id in account_ids
        }

        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            account_id = futures[future]
            try:
                future.result()
            except Exception as e:
                console.print(
                    f"  [red]✗ Error collecting data for account {account_id}: {str(e)}[/]"
                )

    console.print("\n[bold green]✓ Data collection complete![/]")
