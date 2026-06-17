"""Curated cloud recon security tool catalog for `run_custom` usage."""
from __future__ import annotations

from server.agents.executor.recon.tools.security_catalog import normalize_security_catalog

_RAW_CLOUD_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 PASSIVE CLOUD INTELLIGENCE (No Auth Required)
    # ─────────────────────────────────────────────────────────────
    "shodan-cloud": {
        "t": "passive",
        "c": "cloud_asset_discovery",
        "u": "shodan search 'cloud:aws org:\"TARGET\"' --fields ip,port,hostnames,cloud.region,cloud.account 2>/dev/null",
        "d": ["Cloud provider filtering", "Region/account metadata", "Service endpoint discovery", "Historical banner correlation"],
        "tgt": ["aws", "azure", "gcp", "external_assets", "cloud_inventory"],
        "note": "Requires SHODAN_API_KEY env var or --apikey flag"
    },
    
    "censys-cloud": {
        "t": "passive",
        "c": "certificate_service_enum",
        "u": "censys search 'services.tls.certificate.subject.organization: TARGET AND cloud.provider: aws' --fields ip,services.port,cloud 2>/dev/null | jq -c '.[]'",
        "d": ["Certificate transparency for cloud assets", "TLS service enumeration", "Cloud metadata extraction", "SAN/subject name correlation"],
        "tgt": ["tls_cloud_assets", "cert_recon", "service_discovery"],
        "note": "Requires CENSYS_API_ID and CENSYS_API_SECRET env vars"
    },
    
    "securitytrails-cloud": {
        "t": "passive",
        "c": "dns_cloud_correlation",
        "u": "curl -s 'https://api.securitytrails.com/v1/domain/TARGET/subdomains' -H 'APIKEY: (SECRET:securitytrails)' 2>/dev/null | jq -r '.subdomains[]?'",
        "d": ["Subdomain enumeration with cloud hints", "DNS history for cloud migrations", "IP/hostname correlation"],
        "tgt": ["cloud_dns", "subdomain_recon", "migration_mapping"],
        "note": "(SECRET:securitytrails) injected at runtime"
    },
    
    "grayhatwarfare-s3": {
        "t": "passive",
        "c": "public_bucket_discovery",
        "u": "curl -s 'https://buckets.grayhatwarfare.com/buckets/filelist/TARGET' 2>/dev/null | jq -r '.buckets[]?.bucket?'",
        "d": ["Public S3 bucket search", "Object listing (if public)", "Bucket region discovery", "No auth required"],
        "tgt": ["aws_s3", "public_storage", "data_leak_recon"]
    },
    
    "cloudflare-ct": {
        "t": "passive",
        "c": "cert_transparency_enum",
        "u": "curl -s 'https://crt.sh/?q=%.TARGET&output=json' 2>/dev/null | jq -r '.[].name_value' | sort -u",
        "d": ["Certificate transparency log scraping", "Subdomain discovery via certs", "Wildcard domain mapping"],
        "tgt": ["cert_recon", "subdomain_enum", "cloud_hosted_domains"]
    },

    # ─────────────────────────────────────────────────────────────
    # ☁️ AWS RECON (Read-Only Enumeration)
    # ─────────────────────────────────────────────────────────────
    "aws-cli-enum": {
        "t": "aws",
        "c": "resource_enumeration",
        "u": "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name]]' --output text 2>/dev/null",
        "d": ["EC2 instance listing", "Instance type/state mapping", "Tag-based asset grouping", "Region iteration"],
        "tgt": ["aws_ec2", "compute_enum", "asset_inventory"],
        "note": "Requires AWS credentials via env vars or profile"
    },
    
    "aws-s3-enum": {
        "t": "aws",
        "c": "storage_enumeration",
        "u": "aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null",
        "d": ["S3 bucket listing", "Bucket name enumeration", "Creation date mapping", "Region inference via endpoint"],
        "tgt": ["aws_s3", "storage_recon", "bucket_inventory"]
    },
    
    "aws-iam-enum": {
        "t": "aws",
        "c": "identity_enumeration",
        "u": "aws iam list-users --query 'Users[*].[UserName,CreateDate]]' --output text 2>/dev/null",
        "d": ["IAM user listing", "Role/policy enumeration", "Permission boundary discovery", "MFA status mapping"],
        "tgt": ["aws_iam", "identity_recon", "permission_audit"]
    },
    
    "aws-network-enum": {
        "t": "aws",
        "c": "network_topology_discovery",
        "u": "aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock]]' --output text 2>/dev/null",
        "d": ["VPC/subnet enumeration", "Security group rule mapping", "Route table discovery", "NAT/IGW identification"],
        "tgt": ["aws_network", "vpc_recon", "topology_mapping"]
    },
    
    "aws-serverless-enum": {
        "t": "aws",
        "c": "faas_enumeration",
        "u": "aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Handler]]' --output text 2>/dev/null",
        "d": ["Lambda function listing", "Runtime/handler mapping", "Trigger configuration discovery", "Version/alias enumeration"],
        "tgt": ["aws_lambda", "serverless_recon", "faas_inventory"]
    },
    
    "aws-apigateway-enum": {
        "t": "aws",
        "c": "api_gateway_discovery",
        "u": "aws apigateway get-rest-apis --query 'items[*].[name,id]]' --output text 2>/dev/null",
        "d": ["API Gateway REST API listing", "Stage/deployment mapping", "Endpoint URL extraction"],
        "tgt": ["aws_apigateway", "api_recon", "serverless_apis"]
    },
    
    "aws-ecr-enum": {
        "t": "aws",
        "c": "container_registry_enum",
        "u": "aws ecr describe-repositories --query 'repositories[*].[repositoryName,registryId]]' --output text 2>/dev/null",
        "d": ["ECR repository listing", "Image tag enumeration", "Scan status discovery", "Policy structure inspection"],
        "tgt": ["aws_ecr", "container_recon", "registry_inventory"]
    },
    
    "aws-cloudtrail-enum": {
        "t": "aws",
        "c": "logging_configuration_discovery",
        "u": "aws cloudtrail describe-trails --query 'trailList[*].[Name,S3BucketName]]' --output text 2>/dev/null",
        "d": ["CloudTrail trail listing", "Log destination mapping", "Multi-region trail detection"],
        "tgt": ["aws_cloudtrail", "logging_recon", "audit_config"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🪟 AZURE RECON (Read-Only Enumeration)
    # ─────────────────────────────────────────────────────────────
    "az-cli-enum": {
        "t": "azure",
        "c": "resource_enumeration",
        "u": "az vm list --query '[].{Name:name,Location:location,OS:storageProfile.osDisk.osType}' -o tsv 2>/dev/null",
        "d": ["VM/VMSS listing", "OS/type mapping", "Location/region enumeration", "Size/SKU discovery"],
        "tgt": ["azure_vm", "compute_enum", "asset_inventory"],
        "note": "Requires az login or service principal env vars"
    },
    
    "az-storage-enum": {
        "t": "azure",
        "c": "storage_enumeration",
        "u": "az storage account list --query '[].{Name:name,Location:location,Kind:kind}' -o tsv 2>/dev/null",
        "d": ["Storage account listing", "Kind (Blob/File/Table) mapping", "SKU/performance tier discovery"],
        "tgt": ["azure_storage", "blob_recon", "storage_inventory"]
    },
    
    "az-ad-enum": {
        "t": "azure",
        "c": "identity_enumeration",
        "u": "az ad user list --query '[].{UPN:userPrincipalName,DisplayName:displayName}]' -o tsv 2>/dev/null",
        "d": ["Azure AD user listing", "Service principal enumeration", "Group membership mapping"],
        "tgt": ["azure_ad", "identity_recon", "permission_audit"]
    },
    
    "az-network-enum": {
        "t": "azure",
        "c": "network_topology_discovery",
        "u": "az network vnet list --query '[].{Name:name,AddressSpace:addressSpace.addressPrefixes}]' -o tsv 2>/dev/null",
        "d": ["VNet/subnet enumeration", "NSG rule mapping", "Peering connection listing"],
        "tgt": ["azure_network", "vnet_recon", "topology_mapping"]
    },
    
    "az-serverless-enum": {
        "t": "azure",
        "c": "faas_enumeration",
        "u": "az functionapp list --query '[].{Name:name,Location:location,State:state}]' -o tsv 2>/dev/null",
        "d": ["Function App listing", "Runtime/stack mapping", "Consumption/Premium plan discovery"],
        "tgt": ["azure_functions", "serverless_recon", "faas_inventory"]
    },
    
    "az-acr-enum": {
        "t": "azure",
        "c": "container_registry_enum",
        "u": "az acr list --query '[].{Name:name,Location:location,Sku:sku.name}]' -o tsv 2>/dev/null",
        "d": ["ACR registry listing", "SKU/performance tier mapping", "Admin user status discovery"],
        "tgt": ["azure_acr", "container_recon", "registry_inventory"]
    },
    
    "az-keyvault-enum": {
        "t": "azure",
        "c": "secret_vault_discovery",
        "u": "az keyvault list --query '[].{Name:name,Location:location}]' -o tsv 2>/dev/null",
        "d": ["Key Vault listing", "Location/tenant mapping", "Access policy structure inspection"],
        "tgt": ["azure_keyvault", "secret_recon", "vault_inventory"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🟦 GCP RECON (Read-Only Enumeration)
    # ─────────────────────────────────────────────────────────────
    "gcloud-compute-enum": {
        "t": "gcp",
        "c": "compute_enumeration",
        "u": "gcloud compute instances list --format='value(name,zone,status,machineType)' 2>/dev/null",
        "d": ["Compute Engine instance listing", "Zone/region mapping", "Machine type/SKU discovery"],
        "tgt": ["gcp_compute", "vm_enum", "asset_inventory"],
        "note": "Requires gcloud auth or ADC credentials"
    },
    
    "gcloud-storage-enum": {
        "t": "gcp",
        "c": "storage_enumeration",
        "u": "gsutil ls -p PROJECT_ID 2>/dev/null | grep 'gs://'",
        "d": ["GCS bucket listing", "Project association mapping", "Location/type discovery"],
        "tgt": ["gcp_storage", "gcs_recon", "bucket_inventory"]
    },
    
    "gcloud-iam-enum": {
        "t": "gcp",
        "c": "identity_enumeration",
        "u": "gcloud iam service-accounts list --format='value(email,displayName,disabled)' 2>/dev/null",
        "d": ["Service account listing", "IAM role binding discovery", "Policy structure inspection"],
        "tgt": ["gcp_iam", "identity_recon", "permission_audit"]
    },
    
    "gcloud-network-enum": {
        "t": "gcp",
        "c": "network_topology_discovery",
        "u": "gcloud compute networks list --format='value(name,subnetMode)' 2>/dev/null",
        "d": ["VPC/network enumeration", "Subnet CIDR mapping", "Firewall rule structure discovery"],
        "tgt": ["gcp_network", "vpc_recon", "topology_mapping"]
    },
    
    "gcloud-serverless-enum": {
        "t": "gcp",
        "c": "faas_enumeration",
        "u": "gcloud functions list --format='value(name,status,entryPoint)' 2>/dev/null",
        "d": ["Cloud Function listing", "Trigger type mapping", "Runtime/entry point discovery"],
        "tgt": ["gcp_functions", "serverless_recon", "faas_inventory"]
    },
    
    "gcloud-artifact-enum": {
        "t": "gcp",
        "c": "container_registry_enum",
        "u": "gcloud artifacts repositories list --format='value(name,location,format)' 2>/dev/null",
        "d": ["Artifact Registry listing", "Repository format mapping", "Location/region enumeration"],
        "tgt": ["gcp_artifact_registry", "container_recon", "registry_inventory"]
    },
    
    "gcloud-logging-enum": {
        "t": "gcp",
        "c": "logging_configuration_discovery",
        "u": "gcloud logging sinks list --format='value(name,destination)' 2>/dev/null",
        "d": ["Log sink enumeration", "Destination mapping", "Filter rule discovery"],
        "tgt": ["gcp_logging", "audit_config", "logging_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔄 MULTI-CLOUD & AGNOSTIC RECON
    # ─────────────────────────────────────────────────────────────
    "cloud_enum": {
        "t": "multi-cloud",
        "c": "asset_bruteforce_discovery",
        "u": "cloud_enum -k TARGET --aws --azure --gcp --exclude-mine --threads 50 2>/dev/null",
        "d": ["S3/Blob/GCS bucket brute-forcing", "CloudFront/Azure CDN/GCP LB discovery", "Subdomain permutation testing"],
        "tgt": ["multi-cloud", "storage_enum", "public_asset_recon"]
    },
    
    "pacu": {
        "t": "multi-cloud",
        "c": "aws_enumeration_framework",
        "u": "# Interactive: pacu → run aws__enum__account, aws__enum__iam (read-only modules)",
        "d": ["Modular AWS enumeration", "IAM policy analysis", "EC2/S3/RDS discovery", "Lambda/ApiGateway enumeration"],
        "tgt": ["aws", "comprehensive_enum", "security_recon"],
        "note": "Interactive CLI; use --commands-file for batch mode if supported"
    },
    
    "scout-suite": {
        "t": "multi-cloud",
        "c": "cloud_security_audit_recon",
        "u": "scout --provider aws --profile default --no-prompt --format json 2>/dev/null | jq -c '.services[]?.findings[]?'",
        "d": ["Multi-cloud security posture assessment", "Misconfiguration enumeration", "IAM/network/logging audit"],
        "tgt": ["aws", "azure", "gcp", "compliance_recon", "security_posture"],
        "note": "Removed --report-dir; JSON piped to stdout for filtering"
    },
    
    "prowler-audit": {
        "t": "multi-cloud",
        "c": "benchmark_compliance_recon",
        "u": "prowler aws -c cis_1_5 -M json --quiet 2>/dev/null | jq -r '.Checks[]?.CheckID?'",
        "d": ["CIS/NIST benchmark checks", "Misconfiguration enumeration", "IAM/network/logging audit"],
        "tgt": ["aws", "compliance_recon", "security_audit"],
        "note": "Removed --output-folder; JSON to stdout"
    },
    
    "steampipe-cloud": {
        "t": "multi-cloud",
        "c": "sql_based_cloud_query",
        "u": "steampipe query \"select name, region, instance_type from aws_ec2_instance where state_name = 'running'\" --output json 2>/dev/null",
        "d": ["SQL-like querying across cloud providers", "Real-time asset enumeration", "Join across services"],
        "tgt": ["multi-cloud", "asset_inventory", "custom_queries"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🗄️ CLOUD STORAGE RECON (S3/Blob/GCS)
    # ─────────────────────────────────────────────────────────────
    "s3scanner": {
        "t": "storage",
        "c": "s3_bucket_audit",
        "u": "echo '(WORDLIST:buckets)' | xargs -I{} s3scanner scan --bucket {} --output json 2>/dev/null | jq -c '.[]?'",
        "d": ["S3 bucket permission enumeration", "Public read/write/list detection", "ACL/Policy structure extraction"],
        "tgt": ["aws_s3", "permission_recon", "public_storage"],
        "note": "(WORDLIST:buckets) piped via stdin; json output filtered to stdout"
    },
    
    "gcs-bruter": {
        "t": "storage",
        "c": "gcs_bucket_discovery",
        "u": "echo '(WORDLIST:gcs)' | xargs -I{} gsutil ls -b gs://{} 2>/dev/null | grep -oE 'gs://[a-z0-9._-]+'",
        "d": ["GCS bucket name permutation testing", "Project association inference", "IAM policy structure inspection"],
        "tgt": ["gcp_storage", "gcs_buckets", "public_recon"],
        "note": "(WORDLIST:gcs) piped via stdin; no temp files"
    },
    
    "cloud-storage-grep": {
        "t": "storage",
        "c": "pattern_based_bucket_hunt",
        "u": "echo '(MANIFEST:code)' | grep -rEi 's3://|gs://|blob.core.windows.net' - 2>/dev/null | sort -u",
        "d": ["Hardcoded storage endpoint extraction", "Bucket/container name discovery", "Region/path enumeration"],
        "tgt": ["multi-cloud-storage", "code_recon", "endpoint_harvesting"],
        "note": "(MANIFEST:code) piped via stdin; grep reads from -"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 CLOUD IDENTITY & PERMISSION RECON
    # ─────────────────────────────────────────────────────────────
    "aws-iam-access-analyzer": {
        "t": "identity",
        "c": "external_access_discovery",
        "u": "aws accessanalyzer list-analyzers --query 'analyzers[*].[name,status]]' --output text 2>/dev/null",
        "d": ["IAM Access Analyzer enumeration", "External principal discovery", "Resource policy audit"],
        "tgt": ["aws_iam", "external_access", "policy_recon"]
    },
    
    "azure-ad-connect-enum": {
        "t": "identity",
        "c": "hybrid_identity_discovery",
        "u": "az ad sync connector list --query '[].{Name:name,ConnectorType:connectorType}]' -o tsv 2>/dev/null",
        "d": ["Azure AD Connect enumeration", "Sync scope discovery", "Password hash sync status"],
        "tgt": ["azure_ad", "hybrid_identity", "sync_recon"]
    },
    
    "gcp-workload-identity-enum": {
        "t": "identity",
        "c": "k8s_iam_mapping",
        "u": "gcloud iam service-accounts list --filter='description:workload' --format='value(email,displayName)' 2>/dev/null",
        "d": ["Workload Identity service account enumeration", "K8s namespace mapping", "IAM binding structure discovery"],
        "tgt": ["gcp_iam", "k8s_identity", "workload_recon"]
    },
    
    "cloud-privilege-mapper": {
        "t": "identity",
        "c": "permission_graph_discovery",
        "u": "# Custom script: Parse IAM policies → Build privilege graph → Output JSON to stdout",
        "d": ["Policy structure parsing", "Permission inheritance mapping", "Role chaining discovery", "Graph output (JSON)"],
        "tgt": ["multi-cloud-iam", "privilege_recon", "graph_analysis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 CLOUD NETWORKING RECON
    # ─────────────────────────────────────────────────────────────
    "aws-vpc-flow-enum": {
        "t": "network",
        "c": "traffic_logging_discovery",
        "u": "aws ec2 describe-flow-logs --query 'FlowLogs[*].[FlowLogId,LogGroupName]]' --output text 2>/dev/null",
        "d": ["VPC Flow Log enumeration", "Log group destination mapping", "Traffic type config discovery"],
        "tgt": ["aws_network", "flow_logs", "traffic_recon"]
    },
    
    "azure-nsg-audit": {
        "t": "network",
        "c": "firewall_rule_enumeration",
        "u": "az network nsg list --query '[].{Name:name,Rules:securityRules[*].{Name:name,Access:access}}]' -o tsv 2>/dev/null",
        "d": ["NSG rule enumeration", "Direction mapping", "Allow/deny action discovery", "Port/protocol extraction"],
        "tgt": ["azure_network", "nsg_recon", "firewall_audit"]
    },
    
    "gcp-firewall-enum": {
        "t": "network",
        "c": "firewall_rule_discovery",
        "u": "gcloud compute firewall-rules list --format='value(name,direction,allowed[].IPProtocol)' 2>/dev/null",
        "d": ["Firewall rule enumeration", "Direction mapping", "Protocol/port extraction", "Enable/disable status"],
        "tgt": ["gcp_network", "firewall_recon", "rule_audit"]
    },
    
    "cloud-endpoint-mapper": {
        "t": "network",
        "c": "public_endpoint_discovery",
        "u": "echo '(WORDLIST:cloud_assets)' | httpx -silent -cdn -waf -status-code -title -tech-detect -json 2>/dev/null | jq -c '.[]'",
        "d": ["Public cloud endpoint validation", "CDN/WAF detection", "Tech stack fingerprinting", "JSON to stdout"],
        "tgt": ["multi-cloud", "public_endpoints", "web_recon"],
        "note": "(WORDLIST:cloud_assets) piped via stdin; -l flag removed"
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 CLOUD LOGGING & MONITORING RECON
    # ─────────────────────────────────────────────────────────────
    "aws-cloudwatch-enum": {
        "t": "monitoring",
        "c": "log_group_discovery",
        "u": "aws logs describe-log-groups --query 'logGroups[*].[logGroupName,retentionInDays]]' --output text 2>/dev/null",
        "d": ["CloudWatch Log Group enumeration", "Retention policy mapping", "Storage size discovery"],
        "tgt": ["aws_logging", "cloudwatch_recon", "audit_config"]
    },
    
    "azure-monitor-enum": {
        "t": "monitoring",
        "c": "workspace_discovery",
        "u": "az monitor log-analytics workspace list --query '[].{Name:name,Location:location}]' -o tsv 2>/dev/null",
        "d": ["Log Analytics Workspace enumeration", "Retention policy mapping", "Location/region discovery"],
        "tgt": ["azure_monitoring", "log_analytics", "workspace_recon"]
    },
    
    "gcp-cloud-logging-enum": {
        "t": "monitoring",
        "c": "log_bucket_discovery",
        "u": "gcloud logging buckets list --format='value(name,location,retentionDays)' 2>/dev/null",
        "d": ["Log Bucket enumeration", "Retention policy mapping", "Lock status discovery"],
        "tgt": ["gcp_logging", "log_buckets", "audit_config"]
    },
    
    "cloud-metrics-enum": {
        "t": "monitoring",
        "c": "metric_namespace_discovery",
        "u": "aws cloudwatch list-metrics --query 'Metrics[*].Namespace' --output text 2>/dev/null | sort -u",
        "d": ["CloudWatch metric namespace enumeration", "Service correlation", "Dimension key discovery"],
        "tgt": ["aws_monitoring", "metrics_recon", "observability"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📦 INFRASTRUCTURE-AS-CODE CLOUD RECON
    # ─────────────────────────────────────────────────────────────
    "terraform-cloud-enum": {
        "t": "iac",
        "c": "tf_cloud_workspace_discovery",
        "u": "curl -H 'Authorization: Bearer (SECRET:terraform)' -s 'https://app.terraform.io/api/v2/organizations/ORG/workspaces' 2>/dev/null | jq -r '.data[].attributes.name?'",
        "d": ["Terraform Cloud workspace enumeration", "VCS connection mapping", "Run history discovery"],
        "tgt": ["terraform_cloud", "iac_recon", "workspace_enum"],
        "note": "(SECRET:terraform) injected at runtime"
    },
    
    "cloudformation-stack-enum": {
        "t": "iac",
        "c": "cfn_stack_discovery",
        "u": "aws cloudformation list-stacks --query 'StackSummaries[*].[StackName,StackStatus]]' --output text 2>/dev/null",
        "d": ["CloudFormation stack enumeration", "Status mapping", "Template structure inspection"],
        "tgt": ["aws_cfn", "iac_recon", "stack_audit"]
    },
    
    "pulumi-cloud-enum": {
        "t": "iac",
        "c": "pulumi_stack_discovery",
        "u": "pulumi stack ls --json 2>/dev/null | jq -r '.[] | {name: stack, cloud: backend}'?",
        "d": ["Pulumi stack enumeration", "Backend type discovery", "Last update timestamp mapping"],
        "tgt": ["pulumi", "iac_recon", "multi_cloud_iac"]
    },
    
    "iac-secret-scanner": {
        "t": "iac",
        "c": "credential_leak_discovery",
        "u": "echo '(MANIFEST:iac)' | trufflehog xargs --only-verified --json 2>/dev/null | jq -r '.SourceMetadata?.Data?.Filesystem?.path?'",
        "d": ["Hardcoded credential detection in IaC", "API key/secret pattern matching", "Verified secrets only"],
        "tgt": ["multi-cloud-iac", "secret_recon", "credential_audit"],
        "note": "(MANIFEST:iac) piped via stdin; filesystem path replaced with stdin"
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "cloud-recon-pipeline": {
        "t": "automation",
        "c": "multi_provider_toolchain",
        "u": "# Chain via pipes: cloud_enum -k TARGET | httpx -silent | aws-cli-enum | scout-suite --format json",
        "d": ["Cross-cloud asset discovery chaining", "Deduplication across providers", "JSON output to stdout"],
        "tgt": ["multi-cloud", "scalable_recon", "enterprise_discovery", "compliance_audits"]
    },
    
    "docker-cloud-recon": {
        "t": "automation",
        "c": "containerized_toolchain",
        "u": "docker run --rm -i -e AWS_PROFILE=default ghcr.io/prisma-cloud/prowler:latest aws -c cis_1_5 -M json 2>/dev/null | jq -c '.[]?'",
        "d": ["Reproducible cloud recon environments", "Version-pinned tools", "JSON output to stdout"],
        "tgt": ["all", "lab", "client_deliverables", "red_team_ops"]
    },
    
    "custom-cloud-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your script: Query cloud APIs → Correlate assets → Output JSON to stdout",
        "d": ["Custom cloud API integrations", "Asset correlation logic", "Topology graph generation", "Structured JSON output"],
        "tgt": ["enterprise", "red_team", "compliance", "client_specific"]
    }
}

CLOUD_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_CLOUD_RECON_TOOLS)

# ✅ Correct alias for consistency with other catalogs
cloud_tools = CLOUD_RECON_TOOLS
