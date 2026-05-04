"""Curated cloud recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_CLOUD_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 PASSIVE CLOUD INTELLIGENCE (No Auth Required)
    # ─────────────────────────────────────────────────────────────
    "shodan-cloud": {
        "t": "passive",
        "c": "cloud_asset_discovery",
        "u": "shodan search 'cloud:aws org:\"TARGET\"' --fields ip,port,hostnames,cloud.region,cloud.account",
        "d": ["Cloud provider filtering", "Region/account metadata", "Service endpoint discovery", "Historical banner correlation", "Vulnerability tag mapping"],
        "tgt": ["aws", "azure", "gcp", "external_assets", "cloud_inventory"]
    },
    
    "censys-cloud": {
        "t": "passive",
        "c": "certificate_service_enum",
        "u": "censys search 'services.tls.certificate.subject.organization: TARGET AND cloud.provider: aws' --fields ip,services.port,cloud",
        "d": ["Certificate transparency for cloud assets", "TLS service enumeration", "Cloud metadata extraction", "SAN/subject name correlation", "Port/service mapping"],
        "tgt": ["tls_cloud_assets", "cert_recon", "service_discovery"]
    },
    
    "securitytrails-cloud": {
        "t": "passive",
        "c": "dns_cloud_correlation",
        "u": "curl -s 'https://api.securitytrails.com/v1/domain/TARGET.com/subdomains' -H 'APIKEY: KEY' | jq",
        "d": ["Subdomain enumeration with cloud hints", "DNS history for cloud migrations", "IP/hostname correlation", "Cloud provider inference via DNS"],
        "tgt": ["cloud_dns", "subdomain_recon", "migration_mapping"]
    },
    
    "grayhatwarfare-s3": {
        "t": "passive",
        "c": "public_bucket_discovery",
        "u": "curl -s 'https://buckets.grayhatwarfare.com/buckets/filelist/TARGET' | jq '.buckets[]'",
        "d": ["Public S3 bucket search", "Object listing (if public)", "Bucket region discovery", "Last modified metadata", "No auth required"],
        "tgt": ["aws_s3", "public_storage", "data_leak_recon"]
    },
    
    "cloudflare-ct": {
        "t": "passive",
        "c": "cert_transparency_enum",
        "u": "curl -s 'https://crt.sh/?q=%.TARGET.com&output=json' | jq -r '.[].name_value' | sort -u",
        "d": ["Certificate transparency log scraping", "Subdomain discovery via certs", "Cloud-hosted cert correlation", "Wildcard domain mapping"],
        "tgt": ["cert_recon", "subdomain_enum", "cloud_hosted_domains"]
    },

    # ─────────────────────────────────────────────────────────────
    # ☁️ AWS RECON (Read-Only Enumeration)
    # ─────────────────────────────────────────────────────────────
    "aws-cli-enum": {
        "t": "aws",
        "c": "resource_enumeration",
        "u": "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,Tags]]' --output table 2>/dev/null",
        "d": ["EC2 instance listing", "Instance type/state mapping", "Tag-based asset grouping", "Region iteration", "IAM permission boundary check"],
        "tgt": ["aws_ec2", "compute_enum", "asset_inventory"]
    },
    
    "aws-s3-enum": {
        "t": "aws",
        "c": "storage_enumeration",
        "u": "aws s3api list-buckets --query 'Buckets[*].Name' --output table 2>/dev/null",
        "d": ["S3 bucket listing", "Bucket name enumeration", "Creation date mapping", "Region inference via endpoint", "ACL/Policy structure inspection (read-only)"],
        "tgt": ["aws_s3", "storage_recon", "bucket_inventory"]
    },
    
    "aws-iam-enum": {
        "t": "aws",
        "c": "identity_enumeration",
        "u": "aws iam list-users --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]]' --output table 2>/dev/null",
        "d": ["IAM user listing", "Role/policy enumeration", "Permission boundary discovery", "MFA status mapping", "Last activity correlation"],
        "tgt": ["aws_iam", "identity_recon", "permission_audit"]
    },
    
    "aws-network-enum": {
        "t": "aws",
        "c": "network_topology_discovery",
        "u": "aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,Tags]]' --output table 2>/dev/null",
        "d": ["VPC/subnet enumeration", "Security group rule mapping", "Route table discovery", "NAT/IGW identification", "Peering connection mapping"],
        "tgt": ["aws_network", "vpc_recon", "topology_mapping"]
    },
    
    "aws-serverless-enum": {
        "t": "aws",
        "c": "faas_enumeration",
        "u": "aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Handler,Timeout]]' --output table 2>/dev/null",
        "d": ["Lambda function listing", "Runtime/handler mapping", "Trigger configuration discovery", "Environment variable names (non-sensitive)", "Version/alias enumeration"],
        "tgt": ["aws_lambda", "serverless_recon", "faas_inventory"]
    },
    
    "aws-apigateway-enum": {
        "t": "aws",
        "c": "api_gateway_discovery",
        "u": "aws apigateway get-rest-apis --query 'items[*].[name,id,createdDate]]' --output table 2>/dev/null",
        "d": ["API Gateway REST API listing", "Stage/deployment mapping", "Method/resource structure discovery", "Authorizer type identification", "Endpoint URL extraction"],
        "tgt": ["aws_apigateway", "api_recon", "serverless_apis"]
    },
    
    "aws-ecr-enum": {
        "t": "aws",
        "c": "container_registry_enum",
        "u": "aws ecr describe-repositories --query 'repositories[*].[repositoryName,registryId,createdAt]]' --output table 2>/dev/null",
        "d": ["ECR repository listing", "Image tag enumeration", "Scan status discovery", "Policy structure inspection", "Registry ID mapping"],
        "tgt": ["aws_ecr", "container_recon", "registry_inventory"]
    },
    
    "aws-cloudtrail-enum": {
        "t": "aws",
        "c": "logging_configuration_discovery",
        "u": "aws cloudtrail describe-trails --query 'trailList[*].[Name,S3BucketName,IncludeGlobalServiceEvents]]' --output table 2>/dev/null",
        "d": ["CloudTrail trail listing", "Log destination mapping", "Global service event config", "Multi-region trail detection", "Logging status verification"],
        "tgt": ["aws_cloudtrail", "logging_recon", "audit_config"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🪟 AZURE RECON (Read-Only Enumeration)
    # ─────────────────────────────────────────────────────────────
    "az-cli-enum": {
        "t": "azure",
        "c": "resource_enumeration",
        "u": "az vm list --query '[].{Name:name,Location:location,OS:storageProfile.osDisk.osType,Size:hardwareProfile.vmSize}' -o table 2>/dev/null",
        "d": ["VM/VMSS listing", "OS/type mapping", "Location/region enumeration", "Size/SKU discovery", "Tag-based grouping"],
        "tgt": ["azure_vm", "compute_enum", "asset_inventory"]
    },
    
    "az-storage-enum": {
        "t": "azure",
        "c": "storage_enumeration",
        "u": "az storage account list --query '[].{Name:name,Location:location,Kind:kind,Sku:sku.name}' -o table 2>/dev/null",
        "d": ["Storage account listing", "Kind (Blob/File/Table) mapping", "SKU/performance tier discovery", "Location/region enumeration", "Access tier config"],
        "tgt": ["azure_storage", "blob_recon", "storage_inventory"]
    },
    
    "az-ad-enum": {
        "t": "azure",
        "c": "identity_enumeration",
        "u": "az ad user list --query '[].{UPN:userPrincipalName,DisplayName:displayName,AccountEnabled:accountEnabled}' -o table 2>/dev/null",
        "d": ["Azure AD user listing", "Service principal enumeration", "Group membership mapping", "Role assignment discovery", "MFA status correlation"],
        "tgt": ["azure_ad", "identity_recon", "permission_audit"]
    },
    
    "az-network-enum": {
        "t": "azure",
        "c": "network_topology_discovery",
        "u": "az network vnet list --query '[].{Name:name,Location:location,AddressSpace:addressSpace.addressPrefixes}' -o table 2>/dev/null",
        "d": ["VNet/subnet enumeration", "NSG rule mapping", "Route table discovery", "Peering connection listing", "Public IP association"],
        "tgt": ["azure_network", "vnet_recon", "topology_mapping"]
    },
    
    "az-serverless-enum": {
        "t": "azure",
        "c": "faas_enumeration",
        "u": "az functionapp list --query '[].{Name:name,Location:location,Runtime:kind,State:state}' -o table 2>/dev/null",
        "d": ["Function App listing", "Runtime/stack mapping", "Consumption/Premium plan discovery", "Trigger type inference", "Deployment slot enumeration"],
        "tgt": ["azure_functions", "serverless_recon", "faas_inventory"]
    },
    
    "az-acr-enum": {
        "t": "azure",
        "c": "container_registry_enum",
        "u": "az acr list --query '[].{Name:name,Location:location,Sku:sku.name,AdminEnabled:adminUserEnabled}' -o table 2>/dev/null",
        "d": ["ACR registry listing", "SKU/performance tier mapping", "Admin user status discovery", "Geo-replication config", "Webhook/Task enumeration"],
        "tgt": ["azure_acr", "container_recon", "registry_inventory"]
    },
    
    "az-keyvault-enum": {
        "t": "azure",
        "c": "secret_vault_discovery",
        "u": "az keyvault list --query '[].{Name:name,Location:location,Tenant:properties.tenantId}' -o table 2>/dev/null",
        "d": ["Key Vault listing", "Location/tenant mapping", "Access policy structure inspection", "Soft-delete config discovery", "Network rule enumeration"],
        "tgt": ["azure_keyvault", "secret_recon", "vault_inventory"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🟦 GCP RECON (Read-Only Enumeration)
    # ─────────────────────────────────────────────────────────────
    "gcloud-compute-enum": {
        "t": "gcp",
        "c": "compute_enumeration",
        "u": "gcloud compute instances list --format='table(name,zone,status,machineType,disks[].deviceName)' 2>/dev/null",
        "d": ["Compute Engine instance listing", "Zone/region mapping", "Machine type/SKU discovery", "Disk attachment enumeration", "Network interface mapping"],
        "tgt": ["gcp_compute", "vm_enum", "asset_inventory"]
    },
    
    "gcloud-storage-enum": {
        "t": "gcp",
        "c": "storage_enumeration",
        "u": "gsutil ls -p PROJECT_ID 2>/dev/null | grep 'gs://'",
        "d": ["GCS bucket listing", "Project association mapping", "Location/type discovery", "IAM policy structure inspection", "Versioning/config enumeration"],
        "tgt": ["gcp_storage", "gcs_recon", "bucket_inventory"]
    },
    
    "gcloud-iam-enum": {
        "t": "gcp",
        "c": "identity_enumeration",
        "u": "gcloud iam service-accounts list --format='table(email,displayName,disabled)' 2>/dev/null",
        "d": ["Service account listing", "IAM role binding discovery", "Policy structure inspection", "Workload identity mapping", "Key enumeration (names only)"],
        "tgt": ["gcp_iam", "identity_recon", "permission_audit"]
    },
    
    "gcloud-network-enum": {
        "t": "gcp",
        "c": "network_topology_discovery",
        "u": "gcloud compute networks list --format='table(name,subnetMode,description)' 2>/dev/null",
        "d": ["VPC/network enumeration", "Subnet CIDR mapping", "Firewall rule structure discovery", "Cloud NAT/Router listing", "Peering connection mapping"],
        "tgt": ["gcp_network", "vpc_recon", "topology_mapping"]
    },
    
    "gcloud-serverless-enum": {
        "t": "gcp",
        "c": "faas_enumeration",
        "u": "gcloud functions list --format='table(name,status,entryPoint,httpsTrigger.url)' 2>/dev/null",
        "d": ["Cloud Function listing", "Trigger type mapping (HTTP/PubSub)", "Runtime/entry point discovery", "Memory/timeout config", "Ingress settings enumeration"],
        "tgt": ["gcp_functions", "serverless_recon", "faas_inventory"]
    },
    
    "gcloud-artifact-enum": {
        "t": "gcp",
        "c": "container_registry_enum",
        "u": "gcloud artifacts repositories list --format='table(name,location,format,description)' 2>/dev/null",
        "d": ["Artifact Registry listing", "Repository format (Docker/Maven) mapping", "Location/region enumeration", "IAM policy structure inspection", "Package enumeration"],
        "tgt": ["gcp_artifact_registry", "container_recon", "registry_inventory"]
    },
    
    "gcloud-logging-enum": {
        "t": "gcp",
        "c": "logging_configuration_discovery",
        "u": "gcloud logging sinks list --format='table(name,destination,filter)' 2>/dev/null",
        "d": ["Log sink enumeration", "Destination mapping (BigQuery/PubSub/GCS)", "Filter rule discovery", "Exclusion rule listing", "Log bucket configuration"],
        "tgt": ["gcp_logging", "audit_config", "logging_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔄 MULTI-CLOUD & AGNOSTIC RECON
    # ─────────────────────────────────────────────────────────────
    "cloud_enum": {
        "t": "multi-cloud",
        "c": "asset_bruteforce_discovery",
        "u": "cloud_enum -k TARGET --aws --azure --gcp --exclude-mine --threads 50",
        "d": ["S3/Blob/GCS bucket brute-forcing", "CloudFront/Azure CDN/GCP LB discovery", "Subdomain permutation testing", "Public asset identification", "Multi-provider correlation"],
        "tgt": ["multi-cloud", "storage_enum", "public_asset_recon"]
    },
    
    "pacu": {
        "t": "multi-cloud",
        "c": "aws_enumeration_framework",
        "u": "pacu  # Then: run aws__enum__account, aws__enum__iam, aws__enum__ec2 (read-only modules)",
        "d": ["Modular AWS enumeration", "IAM policy analysis (structure)", "EC2/S3/RDS discovery", "Lambda/ApiGateway enumeration", "CloudTrail/Config audit"],
        "tgt": ["aws", "comprehensive_enum", "security_recon"]
    },
    
    "scout-suite": {
        "t": "multi-cloud",
        "c": "cloud_security_audit_recon",
        "u": "scout --provider aws --profile default --no-prompt --report-dir ./scout_report 2>/dev/null",
        "d": ["Multi-cloud security posture assessment", "Misconfiguration enumeration", "IAM policy structure analysis", "Network rule mapping", "Logging config audit"],
        "tgt": ["aws", "azure", "gcp", "compliance_recon", "security_posture"]
    },
    
    "prowler-audit": {
        "t": "multi-cloud",
        "c": "benchmark_compliance_recon",
        "u": "prowler aws -c cis_1_5 -M csv,json --output-folder ./prowler 2>/dev/null",
        "d": ["CIS/NIST benchmark checks", "Misconfiguration enumeration", "IAM/network/logging audit", "Remediation guidance mapping", "Structured report output"],
        "tgt": ["aws", "compliance_recon", "security_audit"]
    },
    
    "steampipe-cloud": {
        "t": "multi-cloud",
        "c": "sql_based_cloud_query",
        "u": "steampipe query \"select name, region, instance_type from aws_ec2_instance where state_name = 'running'\"",
        "d": ["SQL-like querying across cloud providers", "Real-time asset enumeration", "Join across services (EC2+IAM+VPC)", "Plugin architecture (AWS/Azure/GCP/K8s)", "Export to JSON/CSV"],
        "tgt": ["multi-cloud", "asset_inventory", "custom_queries"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🗄️ CLOUD STORAGE RECON (S3/Blob/GCS)
    # ─────────────────────────────────────────────────────────────
    "s3scanner": {
        "t": "storage",
        "c": "s3_bucket_audit",
        "u": "s3scanner scan --bucket-list buckets.txt --output json 2>/dev/null",
        "d": ["S3 bucket permission enumeration", "Public read/write/list detection", "ACL/Policy structure extraction", "Region discovery", "Object listing (if public)"],
        "tgt": ["aws_s3", "permission_recon", "public_storage"]
    },
    
    "blobenum": {
        "t": "storage",
        "c": "azure_blob_discovery",
        "u": "python3 blobenum.py -d TARGET.com -o azure_blobs.txt -t 50 2>/dev/null",
        "d": ["Azure Blob storage name brute-forcing", "Container enumeration", "Anonymous access testing", "Blob listing (if public)", "Metadata extraction"],
        "tgt": ["azure_blobs", "storage_enum", "public_assets"]
    },
    
    "gcs-bruter": {
        "t": "storage",
        "c": "gcs_bucket_discovery",
        "u": "for name in $(cat wordlist.txt); do gsutil ls -b gs://$name 2>/dev/null && echo \"[+] Found: gs://$name\"; done",
        "d": ["GCS bucket name permutation testing", "Project association inference", "IAM policy structure inspection", "Object enumeration (if public)", "Location/type discovery"],
        "tgt": ["gcp_storage", "gcs_buckets", "public_recon"]
    },
    
    "cloud-storage-grep": {
        "t": "storage",
        "c": "pattern_based_bucket_hunt",
        "u": "grep -rEi 's3://|gs://|blob.core.windows.net' app_code/ | sort -u",
        "d": ["Hardcoded storage endpoint extraction", "Bucket/container name discovery", "Region/path enumeration", "Access pattern inference", "Environment mapping (dev/prod)"],
        "tgt": ["multi-cloud-storage", "code_recon", "endpoint_harvesting"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 CLOUD IDENTITY & PERMISSION RECON
    # ─────────────────────────────────────────────────────────────
    "aws-iam-access-analyzer": {
        "t": "identity",
        "c": "external_access_discovery",
        "u": "aws accessanalyzer list-analyzers --query 'analyzers[*].[name,status,arn]' --output table 2>/dev/null",
        "d": ["IAM Access Analyzer enumeration", "External principal discovery", "Resource policy audit", "Finding status mapping", "Archive rule inspection"],
        "tgt": ["aws_iam", "external_access", "policy_recon"]
    },
    
    "azure-ad-connect-enum": {
        "t": "identity",
        "c": "hybrid_identity_discovery",
        "u": "az ad sync connector list --query '[].{Name:name,ConnectorType:connectorType,Enabled:enabled}' -o table 2>/dev/null",
        "d": ["Azure AD Connect enumeration", "Sync scope discovery", "OU filtering mapping", "Password hash sync status", "Federation config inference"],
        "tgt": ["azure_ad", "hybrid_identity", "sync_recon"]
    },
    
    "gcp-workload-identity-enum": {
        "t": "identity",
        "c": "k8s_iam_mapping",
        "u": "gcloud iam service-accounts list --filter='description:workload' --format='table(email,displayName)' 2>/dev/null",
        "d": ["Workload Identity service account enumeration", "K8s namespace mapping", "IAM binding structure discovery", "Token scope inference", "Federation config audit"],
        "tgt": ["gcp_iam", "k8s_identity", "workload_recon"]
    },
    
    "cloud-privilege-mapper": {
        "t": "identity",
        "c": "permission_graph_discovery",
        "u": "# Custom script: Parse IAM policies → Build privilege graph → Identify escalation paths (read-only)",
        "d": ["Policy structure parsing", "Permission inheritance mapping", "Role chaining discovery", "Boundary condition identification", "Graph output (JSON/GraphML)"],
        "tgt": ["multi-cloud-iam", "privilege_recon", "graph_analysis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 CLOUD NETWORKING RECON
    # ─────────────────────────────────────────────────────────────
    "aws-vpc-flow-enum": {
        "t": "network",
        "c": "traffic_logging_discovery",
        "u": "aws ec2 describe-flow-logs --query 'FlowLogs[*].[FlowLogId,LogGroupName,TrafficType,DeliverLogsStatus]' --output table 2>/dev/null",
        "d": ["VPC Flow Log enumeration", "Log group destination mapping", "Traffic type config discovery", "Delivery status verification", "Filter rule inspection"],
        "tgt": ["aws_network", "flow_logs", "traffic_recon"]
    },
    
    "azure-nsg-audit": {
        "t": "network",
        "c": "firewall_rule_enumeration",
        "u": "az network nsg list --query '[].{Name:name,Location:location,Rules:securityRules[].{Name:name,Direction:direction,Access:access}}' -o table 2>/dev/null",
        "d": ["NSG rule enumeration", "Direction (inbound/outbound) mapping", "Allow/deny action discovery", "Port/protocol extraction", "Priority/order mapping"],
        "tgt": ["azure_network", "nsg_recon", "firewall_audit"]
    },
    
    "gcp-firewall-enum": {
        "t": "network",
        "c": "firewall_rule_discovery",
        "u": "gcloud compute firewall-rules list --format='table(name,direction,allowed[].IPProtocol:label=Protocol,targetRanges:label=CIDR,disabled)' 2>/dev/null",
        "d": ["Firewall rule enumeration", "Direction (INGRESS/EGRESS) mapping", "Protocol/port extraction", "Target tag/service account mapping", "Enable/disable status"],
        "tgt": ["gcp_network", "firewall_recon", "rule_audit"]
    },
    
    "cloud-endpoint-mapper": {
        "t": "network",
        "c": "public_endpoint_discovery",
        "u": "httpx -l cloud_assets.txt -cdn -waf -status-code -title -tech-detect -json -o cloud_endpoints.json",
        "d": ["Public cloud endpoint validation", "CDN/WAF detection", "Tech stack fingerprinting", "Response code filtering", "Title/header extraction"],
        "tgt": ["multi-cloud", "public_endpoints", "web_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 CLOUD LOGGING & MONITORING RECON
    # ─────────────────────────────────────────────────────────────
    "aws-cloudwatch-enum": {
        "t": "monitoring",
        "c": "log_group_discovery",
        "u": "aws logs describe-log-groups --query 'logGroups[*].[logGroupName,retentionInDays,storedBytes]' --output table 2>/dev/null",
        "d": ["CloudWatch Log Group enumeration", "Retention policy mapping", "Storage size discovery", "Metric filter structure inspection", "Subscription filter listing"],
        "tgt": ["aws_logging", "cloudwatch_recon", "audit_config"]
    },
    
    "azure-monitor-enum": {
        "t": "monitoring",
        "c": "workspace_discovery",
        "u": "az monitor log-analytics workspace list --query '[].{Name:name,Location:location,Retention:retentionInDays}' -o table 2>/dev/null",
        "d": ["Log Analytics Workspace enumeration", "Retention policy mapping", "Location/region discovery", "Data collection rule association", "Table schema inference"],
        "tgt": ["azure_monitoring", "log_analytics", "workspace_recon"]
    },
    
    "gcp-cloud-logging-enum": {
        "t": "monitoring",
        "c": "log_bucket_discovery",
        "u": "gcloud logging buckets list --format='table(name,location,retentionDays,locked)' 2>/dev/null",
        "d": ["Log Bucket enumeration", "Retention policy mapping", "Lock status discovery", "Location/region enumeration", "View configuration inspection"],
        "tgt": ["gcp_logging", "log_buckets", "audit_config"]
    },
    
    "cloud-metrics-enum": {
        "t": "monitoring",
        "c": "metric_namespace_discovery",
        "u": "aws cloudwatch list-metrics --query 'Metrics[*].Namespace' --output table 2>/dev/null | sort -u",
        "d": ["CloudWatch metric namespace enumeration", "Service correlation (EC2/RDS/Lambda)", "Dimension key discovery", "Alarm structure inspection", "Dashboard listing"],
        "tgt": ["aws_monitoring", "metrics_recon", "observability"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📦 INFRASTRUCTURE-AS-CODE CLOUD RECON
    # ─────────────────────────────────────────────────────────────
    "terraform-cloud-enum": {
        "t": "iac",
        "c": "tf_cloud_workspace_discovery",
        "u": "curl -H 'Authorization: Bearer TOKEN' https://app.terraform.io/api/v2/organizations/ORG/workspaces | jq '.data[].attributes.name'",
        "d": ["Terraform Cloud workspace enumeration", "VCS connection mapping", "Run history discovery", "Variable set enumeration", "Agent pool association"],
        "tgt": ["terraform_cloud", "iac_recon", "workspace_enum"]
    },
    
    "cloudformation-stack-enum": {
        "t": "iac",
        "c": "cfn_stack_discovery",
        "u": "aws cloudformation list-stacks --query 'StackSummaries[*].[StackName,StackStatus,CreationTime]' --output table 2>/dev/null",
        "d": ["CloudFormation stack enumeration", "Status (CREATE_COMPLETE/ROLLBACK) mapping", "Template structure inspection", "Parameter name discovery", "Output variable enumeration"],
        "tgt": ["aws_cfn", "iac_recon", "stack_audit"]
    },
    
    "pulumi-cloud-enum": {
        "t": "iac",
        "c": "pulumi_stack_discovery",
        "u": "pulumi stack ls --json 2>/dev/null | jq '.[] | {name: stack, cloud: backend, lastUpdate: lastUpdate}'",
        "d": ["Pulumi stack enumeration", "Backend type discovery (HTTP/S3/Azure)", "Last update timestamp mapping", "Resource count inference", "Config variable names"],
        "tgt": ["pulumi", "iac_recon", "multi_cloud_iac"]
    },
    
    "iac-secret-scanner": {
        "t": "iac",
        "c": "credential_leak_discovery",
        "u": "trufflehog filesystem ./iac_configs/ --only-verified --json 2>/dev/null",
        "d": ["Hardcoded credential detection in IaC", "API key/secret pattern matching", "Variable interpolation analysis", "Backend config audit", "Verified secrets only"],
        "tgt": ["multi-cloud-iac", "secret_recon", "credential_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "cloud-recon-pipeline": {
        "t": "automation",
        "c": "multi_provider_toolchain",
        "u": "# Your script: cloud_enum | httpx | aws-cli-enum | scout-suite --report-dir ./final",
        "d": ["Cross-cloud asset discovery chaining", "Deduplication across providers", "JSON/YAML report aggregation", "CI/CD integration", "Engagement-specific filtering"],
        "tgt": ["multi-cloud", "scalable_recon", "enterprise_discovery", "compliance_audits"]
    },
    
    "docker-cloud-recon": {
        "t": "automation",
        "c": "containerized_toolchain",
        "u": "docker run -v $(pwd):/data -e AWS_PROFILE=default ghcr.io/prisma-cloud/prowler aws -c cis_1_5 -M json",
        "d": ["Reproducible cloud recon environments", "Version-pinned tools", "Clean workspaces", "Pre-configured cloud CLI profiles", "No host pollution"],
        "tgt": ["all", "lab", "client_deliverables", "red_team_ops"]
    },
    
    "custom-cloud-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your Python/Go script: Query cloud APIs → Correlate assets → Generate topology graph + risk score",
        "d": ["Custom cloud API integrations", "Asset correlation logic", "Topology graph generation", "Risk scoring based on exposure", "Structured output (JSON/GraphML/CSV)"],
        "tgt": ["enterprise", "red_team", "compliance", "client_specific"]
    }
}

CLOUD_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_CLOUD_RECON_TOOLS)

network_tools = CLOUD_RECON_TOOLS
