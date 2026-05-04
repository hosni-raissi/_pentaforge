"""Curated infrastructure recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_INFRA_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # ☁️ CLOUD INFRASTRUCTURE RECON (AWS/Azure/GCP)
    # ─────────────────────────────────────────────────────────────
    "cloud_enum": {
        "t": "cloud",
        "c": "multi_cloud_asset_discovery",
        "u": "cloud_enum -k TARGET_KEYWORD --azure --gcp --aws --exclude-mine",
        "d": ["AWS S3 bucket enumeration", "Azure Blob storage discovery", "GCP bucket scanning", "CloudFront/CloudFlare mapping", "Subdomain brute-forcing"],
        "tgt": ["aws", "azure", "gcp", "cloud_storage", "cdn_assets"]
    },
    
    "aws-cli-recon": {
        "t": "cloud",
        "c": "aws_resource_enumeration",
        "u": "aws s3 ls 2>/dev/null; aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,Tags]' --output table",
        "d": ["S3 bucket listing", "EC2 instance enumeration", "IAM role/policy discovery", "Security group mapping", "VPC/subnet topology"],
        "tgt": ["aws", "iam_recon", "ec2_enum", "s3_discovery"]
    },
    
    "azure-cli-recon": {
        "t": "cloud",
        "c": "azure_resource_enumeration",
        "u": "az storage account list --query '[].name' -o table; az vm list --query '[].{Name:name,OS:storageProfile.osDisk.osType}' -o table",
        "d": ["Storage account enumeration", "VM/VMSS discovery", "Resource group mapping", "Azure AD tenant info", "Key Vault listing"],
        "tgt": ["azure", "storage_accounts", "vm_enum", "aad_recon"]
    },
    
    "gcp-cli-recon": {
        "t": "cloud",
        "c": "gcp_resource_enumeration",
        "u": "gcloud compute instances list --format='table(name,zone,status)'; gsutil ls -p PROJECT_ID",
        "d": ["Compute Engine instance listing", "GCS bucket enumeration", "IAM policy discovery", "Service account mapping", "Cloud Function discovery"],
        "tgt": ["gcp", "compute_engine", "gcs_buckets", "iam_enum"]
    },
    
    "pacu": {
        "t": "cloud",
        "c": "aws_enumeration_framework",
        "u": "pacu  # Then: run aws__enum__account, aws__enum__iam, aws__enum__ec2",
        "d": ["Modular AWS enumeration", "IAM policy analysis", "EC2/S3/RDS discovery", "Lambda function enumeration", "CloudTrail config check"],
        "tgt": ["aws", "iam_audit", "service_enum", "cloud_security_recon"]
    },
    
    "stormspotter": {
        "t": "cloud",
        "c": "azure_ad_graph_recon",
        "u": "stormspotter -u USER -p PASS -t TENANT  # Or with token",
        "d": ["Azure AD enumeration", "Service principal mapping", "Role assignment graph", "Conditional access policy discovery", "Visual graph output"],
        "tgt": ["azure", "azure_ad", "identity_recon", "graph_analysis"]
    },
    
    "gcpbucketbrute": {
        "t": "cloud",
        "c": "gcs_bucket_enumeration",
        "u": "python3 gcpbucketbrute.py -k TARGET_KEYWORD -p permutations.txt",
        "d": ["GCS bucket name brute-forcing", "Permission enumeration (read/write/list)", "Public bucket discovery", "Object listing"],
        "tgt": ["gcp", "gcs_buckets", "storage_recon", "public_assets"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🐳 CONTAINER & KUBERNETES RECON
    # ─────────────────────────────────────────────────────────────
    "kube-hunter": {
        "t": "k8s",
        "c": "kubernetes_vulnerability_recon",
        "u": "kube-hunter --remote TARGET_IP --report json",
        "d": ["K8s API server enumeration", "Pod/service discovery", "RBAC permission mapping", "Exposed dashboard detection", "CVE correlation (read-only)"],
        "tgt": ["kubernetes", "api_server", "rbac_enum", "cluster_recon"]
    },
    
    "kubescan": {
        "t": "k8s",
        "c": "k8s_risk_assessment",
        "u": "kubescan.sh --namespace default --output report.html",
        "d": ["Pod security context analysis", "Service account privilege mapping", "Network policy enumeration", "Secret exposure detection", "Risk scoring"],
        "tgt": ["kubernetes", "security_context", "rbac_audit", "compliance_recon"]
    },
    
    "trivy-k8s": {
        "t": "k8s",
        "c": "cluster_config_scanning",
        "u": "trivy k8s --report=summary cluster",
        "d": ["K8s manifest scanning", "Misconfiguration detection", "CVE mapping for images", "Policy compliance check", "JSON/YAML report output"],
        "tgt": ["kubernetes", "config_audit", "image_scan", "policy_recon"]
    },
    
    "docker-enum": {
        "t": "container",
        "c": "docker_daemon_recon",
        "u": "curl --unix-socket /var/run/docker.sock http://localhost/version; curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
        "d": ["Docker daemon API enumeration", "Container listing", "Image metadata extraction", "Volume/network mapping", "Exposed socket detection"],
        "tgt": ["docker", "daemon_api", "container_enum", "socket_recon"]
    },
    
    "container-registry-scan": {
        "t": "container",
        "c": "registry_enumeration",
        "u": "crane ls TARGET_REGISTRY/repo 2>/dev/null; crane manifest TARGET_REGISTRY/repo:tag | jq",
        "d": ["Container registry listing", "Image tag enumeration", "Manifest/layer inspection", "Public registry scanning", "Authentication requirement detection"],
        "tgt": ["docker_hub", "ecr", "gcr", "acr", "registry_recon"]
    },
    
    "falco-rules-audit": {
        "t": "container",
        "c": "runtime_policy_recon",
        "u": "grep -r 'rule\\|list\\|macro' /etc/falco/*.yaml 2>/dev/null | head -50",
        "d": ["Falco rule enumeration", "Runtime policy discovery", "Alert condition mapping", "Syscall monitoring config", "Security rule auditing"],
        "tgt": ["kubernetes", "runtime_security", "policy_recon", "detection_rules"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔁 CI/CD PIPELINE RECON
    # ─────────────────────────────────────────────────────────────
    "github-recon": {
        "t": "cicd",
        "c": "github_asset_enumeration",
        "u": "curl -H 'Authorization: token TOKEN' https://api.github.com/orgs/ORG/repos | jq '.[].name'",
        "d": ["Repository enumeration", "Workflow file discovery (.github/workflows/)", "Secret scanning (public repos)", "Branch/tag listing", "Contributor mapping"],
        "tgt": ["github", "gitlab", "bitbucket", "repo_enum", "workflow_discovery"]
    },
    
    "gitlab-recon": {
        "t": "cicd",
        "c": "gitlab_pipeline_enum",
        "u": "curl --header 'PRIVATE-TOKEN: TOKEN' https://gitlab.example.com/api/v4/projects | jq '.[].path'",
        "d": ["Project enumeration", "CI/CD pipeline discovery", "Runner configuration mapping", "Variable enumeration (non-sensitive)", "Job artifact listing"],
        "tgt": ["gitlab", "ci_cd", "pipeline_recon", "runner_enum"]
    },
    
    "jenkins-recon": {
        "t": "cicd",
        "c": "jenkins_instance_enum",
        "u": "curl -s http://TARGET:8080/api/json?pretty=true | jq '.jobs[].name'",
        "d": ["Jenkins job enumeration", "Build history discovery", "Plugin version mapping", "Credential store detection (read-only)", "Node/agent listing"],
        "tgt": ["jenkins", "ci_cd", "build_server", "plugin_enum"]
    },
    
    "circleci-recon": {
        "t": "cicd",
        "c": "circleci_pipeline_discovery",
        "u": "curl -H 'Circle-Token: TOKEN' https://circleci.com/api/v2/project/gh/ORG/REPO/pipeline | jq",
        "d": ["Pipeline enumeration", "Workflow/job mapping", "Context/variable discovery (names only)", "Executor type identification", "Build artifact listing"],
        "tgt": ["circleci", "ci_cd", "pipeline_recon", "workflow_enum"]
    },
    
    "github-actions-audit": {
        "t": "cicd",
        "c": "workflow_security_recon",
        "u": "find .github/workflows -name '*.yml' -exec grep -H 'uses:\\|env:\\|secrets:' {} \\;",
        "d": ["GitHub Actions workflow analysis", "Third-party action enumeration", "Environment variable discovery", "Secret usage mapping", "Permission scope audit"],
        "tgt": ["github_actions", "workflow_audit", "action_enum", "permission_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 DNS/CDN/WAF INFRASTRUCTURE RECON
    # ─────────────────────────────────────────────────────────────
    "dnsrecon-infra": {
        "t": "dns",
        "c": "infrastructure_dns_enum",
        "u": "dnsrecon -d TARGET.com -t axfr,std,brt,goo,mname,srv",
        "d": ["Zone transfer testing", "SRV record enumeration", "Mail server discovery", "Name server mapping", "Brute subdomain discovery"],
        "tgt": ["dns_infra", "zone_transfer", "srv_records", "ns_enum"]
    },
    
    "cdn-fingerprint": {
        "t": "cdn",
        "c": "cdn_waf_detection",
        "u": "httpx -u TARGET_LIST -cdn -waf -json -o cdn_report.json",
        "d": ["CDN provider detection (CloudFlare/Akamai/Fastly)", "WAF identification", "Edge location mapping", "Cache header analysis", "Origin IP inference"],
        "tgt": ["cdn", "waf", "edge_infra", "origin_discovery"]
    },
    
    "wafw00f-infra": {
        "t": "waf",
        "c": "waf_fingerprinting",
        "u": "wafw00f -a -v http://TARGET",
        "d": ["WAF product identification", "Vendor/version detection", "Protection mechanism mapping", "Bypass strategy inference (recon only)"],
        "tgt": ["waf", "security_infra", "protection_enum", "vendor_id"]
    },
    
    "shodan-infra": {
        "t": "passive",
        "c": "infrastructure_intelligence",
        "u": "shodan search 'org:\"TARGET_ORG\" product:\"nginx\"' --fields ip,port,hostnames,org",
        "d": ["Internet-wide asset discovery", "Service/version enumeration", "Geolocation mapping", "Vulnerability tag correlation", "Historical banner data"],
        "tgt": ["external_infra", "asset_inventory", "service_enum", "vuln_correlation"]
    },
    
    "censys-infra": {
        "t": "passive",
        "c": "certificate_service_recon",
        "u": "censys search 'services.tls.certificate.subject.organization: TARGET' --fields ip,services.port,services.tls.certificate.names",
        "d": ["Certificate transparency enumeration", "TLS service discovery", "SAN/subject name extraction", "Port/service mapping", "ASN/organization correlation"],
        "tgt": ["tls_infra", "cert_recon", "service_discovery", "org_mapping"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🗄️ STORAGE INFRASTRUCTURE RECON
    # ─────────────────────────────────────────────────────────────
    "s3-enumerator": {
        "t": "storage",
        "c": "s3_bucket_discovery",
        "u": "python3 s3-enumerator.py -b TARGET_KEYWORD -r us-east-1 -o results.txt",
        "d": ["AWS S3 bucket brute-forcing", "Region enumeration", "Permission testing (read/list/write)", "Object listing", "Public bucket identification"],
        "tgt": ["aws_s3", "bucket_enum", "storage_recon", "public_assets"]
    },
    
    "blobenum": {
        "t": "storage",
        "c": "azure_blob_enumeration",
        "u": "python3 blobenum.py -d TARGET.com -o azure_blobs.txt",
        "d": ["Azure Blob storage name brute-forcing", "Container enumeration", "Permission testing (anonymous access)", "Blob listing", "Public container discovery"],
        "tgt": ["azure_blobs", "storage_enum", "container_recon", "public_assets"]
    },
    
    "gcs-bruter": {
        "t": "storage",
        "c": "gcs_bucket_discovery",
        "u": "for prefix in TARGET target-app targetapp; do for suffix in bucket storage data; do echo \"${prefix}-${suffix}\"; done; done | gsutil ls 2>/dev/null",
        "d": ["GCS bucket name permutation testing", "Project association mapping", "IAM policy discovery (if accessible)", "Object enumeration", "Public bucket identification"],
        "tgt": ["gcp_storage", "gcs_buckets", "bucket_enum", "public_recon"]
    },
    
    "nfs-enum": {
        "t": "storage",
        "c": "nfs_share_discovery",
        "u": "showmount -e TARGET_IP 2>/dev/null; rpcinfo -p TARGET_IP 2>/dev/null | grep nfs",
        "d": ["NFS export listing", "Mount point enumeration", "Permission mapping (ro/rw)", "RPC service verification", "Network share discovery"],
        "tgt": ["nfs", "file_shares", "unix_storage", "network_enum"]
    },
    
    "smb-share-enum": {
        "t": "storage",
        "c": "smb_share_discovery",
        "u": "smbclient -L //TARGET_IP -N 2>/dev/null | grep -E 'Disk|Share'",
        "d": ["SMB share enumeration", "Null session testing", "Share permission discovery", "Comment/description extraction", "Guest access verification"],
        "tgt": ["smb", "windows_shares", "file_server", "share_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # ⚡ SERVERLESS & FUNCTION RECON
    # ─────────────────────────────────────────────────────────────
    "serverless-recon": {
        "t": "serverless",
        "c": "function_enumeration",
        "u": "aws lambda list-functions --query 'Functions[*].FunctionName' --output table 2>/dev/null",
        "d": ["Lambda/Azure Function/GCF listing", "Runtime/environment discovery", "Trigger mapping (API Gateway/EventBridge)", "Permission/role enumeration", "Version/alias discovery"],
        "tgt": ["aws_lambda", "azure_functions", "gcp_cloud_functions", "faas_recon"]
    },
    
    "apigateway-enum": {
        "t": "serverless",
        "c": "api_gateway_discovery",
        "u": "aws apigateway get-rest-apis --query 'items[*].{Name:name,ID:id}' --output table 2>/dev/null",
        "d": ["API Gateway REST API enumeration", "Stage/deployment mapping", "Method/resource discovery", "Authorizer configuration inspection", "Endpoint URL extraction"],
        "tgt": ["aws_apigateway", "serverless_apis", "gateway_recon", "endpoint_enum"]
    },
    
    "cloudfunction-perm-check": {
        "t": "serverless",
        "c": "function_permission_audit",
        "u": "gcloud functions describe FUNCTION_NAME --region REGION --format='yaml(entryPoint,availableMemoryMb,timeout,eventTrigger)'",
        "d": ["Cloud Function configuration inspection", "Trigger event mapping", "Memory/timeout settings", "IAM binding discovery", "Environment variable names (non-sensitive)"],
        "tgt": ["gcp_functions", "permission_recon", "config_audit", "trigger_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📦 INFRASTRUCTURE-AS-CODE RECON
    # ─────────────────────────────────────────────────────────────
    "terraform-state-audit": {
        "t": "iac",
        "c": "tf_state_enumeration",
        "u": "# If state file accessible: terraform show -json state.tfstate | jq '.resources[].type'",
        "d": ["Terraform resource enumeration", "Provider/module discovery", "Output variable mapping", "Backend configuration inspection", "Sensitive value detection (names only)"],
        "tgt": ["terraform", "iac_recon", "state_audit", "resource_enum"]
    },
    
    "cloudformation-lint-recon": {
        "t": "iac",
        "c": "cfn_template_analysis",
        "u": "cfn-lint template.yaml --info 2>/dev/null | grep -E 'resource|parameter|output'",
        "d": ["CloudFormation template parsing", "Resource type enumeration", "Parameter/Output mapping", "IAM policy discovery (structure only)", "Intrinsic function usage"],
        "tgt": ["cloudformation", "aws_iac", "template_recon", "resource_mapping"]
    },
    
    "pulumi-stack-inspect": {
        "t": "iac",
        "c": "pulumi_state_recon",
        "u": "pulumi stack --show-secrets=false 2>/dev/null | head -30",
        "d": ["Pulumi stack enumeration", "Resource summary extraction", "Configuration variable names", "Provider/plugin version mapping", "Stack output discovery (non-sensitive)"],
        "tgt": ["pulumi", "iac_recon", "stack_enum", "multi_cloud_iac"]
    },
    
    "ansible-inventory-audit": {
        "t": "iac",
        "c": "ansible_host_enum",
        "u": "ansible-inventory --list -i inventory.ini 2>/dev/null | jq 'keys'",
        "d": ["Ansible host/group enumeration", "Variable name discovery", "Role/module usage mapping", "Connection method identification (SSH/winrm)", "Vault file detection"],
        "tgt": ["ansible", "config_management", "host_inventory", "automation_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 MONITORING & LOGGING INFRA RECON
    # ─────────────────────────────────────────────────────────────
    "prometheus-metrics-enum": {
        "t": "monitoring",
        "c": "prometheus_endpoint_discovery",
        "u": "curl -s http://TARGET:9090/api/v1/label/__name__/values | jq",
        "d": ["Prometheus metric name enumeration", "Target/instance discovery", "Job label mapping", "Scrape config inference", "Alert rule discovery (via API)"],
        "tgt": ["prometheus", "metrics_recon", "monitoring_enum", "observability"]
    },
    
    "grafana-datasource-recon": {
        "t": "monitoring",
        "c": "grafana_config_discovery",
        "u": "curl -s -H 'Authorization: Bearer TOKEN' http://TARGET:3000/api/datasources | jq '.[].type'",
        "d": ["Grafana datasource enumeration", "Backend service mapping (Prometheus/ES/Influx)", "Dashboard listing", "User/role discovery", "Alert notification channel names"],
        "tgt": ["grafana", "dashboard_recon", "datasource_enum", "observability"]
    },
    
    "elasticsearch-enum": {
        "t": "logging",
        "c": "es_cluster_discovery",
        "u": "curl -s http://TARGET:9200/_cat/nodes?v; curl -s http://TARGET:9200/_cat/indices?v",
        "d": ["Elasticsearch node enumeration", "Index listing", "Shard/replica mapping", "Plugin/version discovery", "Cluster health/status"],
        "tgt": ["elasticsearch", "logging_infra", "cluster_recon", "index_enum"]
    },
    
    "splunk-recon": {
        "t": "logging",
        "c": "splunk_instance_enum",
        "u": "curl -k -s https://TARGET:8089/services/server/info?output_mode=json | jq '.entry[0].content.version'",
        "d": ["Splunk management port enumeration", "Version/build discovery", "License/type identification", "App/add-on listing", "Indexer cluster mapping"],
        "tgt": ["splunk", "siem_recon", "logging_infra", "management_api"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 NETWORK INFRASTRUCTURE RECON (Routers/Switches/Firewalls)
    # ─────────────────────────────────────────────────────────────
    "snmp-infra-enum": {
        "t": "network",
        "c": "snmp_device_discovery",
        "u": "snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.1 | grep -E 'sysName|sysDescr|sysLocation'",
        "d": ["SNMP v2c public community query", "Device name/model/location extraction", "Interface enumeration", "Routing table discovery", "ARP table mapping"],
        "tgt": ["network_devices", "snmp_recon", "cisco", "juniper", "arista"]
    },
    
    "cisco-recon": {
        "t": "network",
        "c": "cisco_device_enum",
        "u": "nmap -sV --script cisco-* -Pn TARGET_IP 2>/dev/null | grep -E 'script|version'",
        "d": ["Cisco device version detection", "IOS/IOS-XE/NX-OS identification", "SNMP/SSH/Telnet service mapping", "CVE correlation (read-only)", "Config backup detection"],
        "tgt": ["cisco", "network_devices", "ios_enum", "switch_recon"]
    },
    
    "firewall-rule-audit": {
        "t": "network",
        "c": "firewall_config_recon",
        "u": "# If management API accessible: curl -k https://TARGET/api/?key=API_KEY&action=show&type=config",
        "d": ["Firewall rule enumeration (structure only)", "Zone/interface mapping", "NAT policy discovery", "Object group listing", "Admin user enumeration (names)"],
        "tgt": ["palo_alto", "fortinet", "checkpoint", "firewall_recon"]
    },
    
    "lldp-discovery": {
        "t": "network",
        "c": "layer2_neighbor_enum",
        "u": "tcpdump -i eth0 -nn -vv ether[20:2] == 0x88cc 2>/dev/null | grep -E 'Chassis ID|Port ID|System Name'",
        "d": ["LLDP packet capture", "Neighbor device discovery", "Port/interface mapping", "System name/capability extraction", "Network topology inference"],
        "tgt": ["layer2", "switch_enum", "topology_recon", "neighbor_discovery"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "infra-recon-pipeline": {
        "t": "automation",
        "c": "multi_cloud_toolchain",
        "u": "# Your script: subfinder | httpx | cloud_enum | kube-hunter | trivy k8s",
        "d": ["Cross-cloud asset discovery chaining", "Deduplication across sources", "JSON/YAML report aggregation", "CI/CD integration", "Engagement-specific filtering"],
        "tgt": ["multi_cloud", "scalable_recon", "enterprise_discovery", "bug_bounty"]
    },
    
    "docker-infra-recon": {
        "t": "automation",
        "c": "containerized_toolchain",
        "u": "docker run -v $(pwd):/data ghcr.io/projectdiscovery/httpx -list targets.txt -cdn -waf -json",
        "d": ["Reproducible infra recon environments", "Version-pinned tools", "Clean workspaces", "Pre-configured cloud CLI profiles", "No host pollution"],
        "tgt": ["all", "lab", "client_deliverables", "compliance_audits"]
    },
    
    "custom-infra-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your Python/Go script: Parse cloud APIs → Correlate assets → Generate topology graph",
        "d": ["Custom cloud API integrations", "Asset correlation logic", "Topology graph generation", "Risk scoring based on exposure", "Structured output (JSON/GraphML)"],
        "tgt": ["enterprise", "red_team", "compliance", "client_specific"]
    }
}

INFRA_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_INFRA_RECON_TOOLS)

network_tools = INFRA_RECON_TOOLS
