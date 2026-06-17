"""Curated infrastructure recon security tool catalog for `run_custom` usage."""
from __future__ import annotations

from server.agents.executor.recon.tools.security_catalog import normalize_security_catalog

_RAW_INFRA_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # ☁️ CLOUD INFRASTRUCTURE RECON (AWS/Azure/GCP)
    # ─────────────────────────────────────────────────────────────
    "cloud_enum": {
        "t": "cloud",
        "c": "multi_cloud_asset_discovery",
        "u": "cloud_enum -k TARGET --azure --gcp --aws --exclude-mine 2>/dev/null",
        "d": ["AWS S3 bucket enumeration", "Azure Blob storage discovery", "GCP bucket scanning", "Subdomain brute-forcing"],
        "tgt": ["aws", "azure", "gcp", "cloud_storage", "cdn_assets"]
    },
    
    "aws-cli-recon": {
        "t": "cloud",
        "c": "aws_resource_enumeration",
        "u": "aws s3 ls 2>/dev/null; aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress]]' --output text",
        "d": ["S3 bucket listing", "EC2 instance enumeration", "IAM role/policy discovery", "Security group mapping"],
        "tgt": ["aws", "iam_recon", "ec2_enum", "s3_discovery"],
        "note": "Requires AWS credentials via env vars or profile"
    },
    
    "azure-cli-recon": {
        "t": "cloud",
        "c": "azure_resource_enumeration",
        "u": "az storage account list --query '[].name' -o tsv 2>/dev/null; az vm list --query '[].{Name:name,OS:storageProfile.osDisk.osType}]' -o tsv",
        "d": ["Storage account enumeration", "VM/VMSS discovery", "Resource group mapping", "Key Vault listing"],
        "tgt": ["azure", "storage_accounts", "vm_enum", "aad_recon"],
        "note": "Requires az login or service principal env vars"
    },
    
    "gcp-cli-recon": {
        "t": "cloud",
        "c": "gcp_resource_enumeration",
        "u": "gcloud compute instances list --format='value(name,zone,status)' 2>/dev/null; gsutil ls -p PROJECT_ID 2>/dev/null | grep 'gs://'",
        "d": ["Compute Engine instance listing", "GCS bucket enumeration", "IAM policy discovery", "Service account mapping"],
        "tgt": ["gcp", "compute_engine", "gcs_buckets", "iam_enum"],
        "note": "Requires gcloud auth or ADC credentials"
    },
    
    "pacu": {
        "t": "cloud",
        "c": "aws_enumeration_framework",
        "u": "# Interactive: pacu → run aws__enum__account, aws__enum__iam (read-only modules)",
        "d": ["Modular AWS enumeration", "IAM policy analysis", "EC2/S3/RDS discovery", "Lambda function enumeration"],
        "tgt": ["aws", "iam_audit", "service_enum", "cloud_security_recon"],
        "note": "Interactive CLI; use --commands-file for batch mode if supported"
    },
    
    "stormspotter": {
        "t": "cloud",
        "c": "azure_ad_graph_recon",
        "u": "# Interactive: stormspotter -u USER -p PASS -t TENANT → generates local graph DB",
        "d": ["Azure AD enumeration", "Service principal mapping", "Role assignment graph", "Conditional access policy discovery"],
        "tgt": ["azure", "azure_ad", "identity_recon", "graph_analysis"],
        "note": "Generates local Neo4j DB; use --report-format json if available for stdout"
    },
    
    "gcpbucketbrute": {
        "t": "cloud",
        "c": "gcs_bucket_enumeration",
        "u": "echo '(WORDLIST:gcs_permutations)' | xargs -I{} gsutil ls -b gs://{} 2>/dev/null | grep -oE 'gs://[a-z0-9._-]+' | sort -u",
        "d": ["GCS bucket name brute-forcing", "Permission enumeration", "Public bucket discovery", "Object listing"],
        "tgt": ["gcp", "gcs_buckets", "storage_recon", "public_assets"],
        "note": "(WORDLIST:gcs_permutations) piped via stdin; no -p file flag"
    },

    # ─────────────────────────────────────────────────────────────
    # 🐳 CONTAINER & KUBERNETES RECON
    # ─────────────────────────────────────────────────────────────
    "kube-hunter": {
        "t": "k8s",
        "c": "kubernetes_vulnerability_recon",
        "u": "kube-hunter --remote TARGET_IP --report json --log-file none 2>/dev/null | jq -c '.vulnerabilities[]?'",
        "d": ["K8s API server enumeration", "Pod/service discovery", "RBAC permission mapping", "Exposed dashboard detection"],
        "tgt": ["kubernetes", "api_server", "rbac_enum", "cluster_recon"]
    },
    
    "trivy-k8s": {
        "t": "k8s",
        "c": "cluster_config_scanning",
        "u": "trivy k8s --report=summary cluster --format json 2>/dev/null | jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID?'",
        "d": ["K8s manifest scanning", "Misconfiguration detection", "CVE mapping for images", "Policy compliance check"],
        "tgt": ["kubernetes", "config_audit", "image_scan", "policy_recon"]
    },
    
    "docker-enum": {
        "t": "container",
        "c": "docker_daemon_recon",
        "u": "curl --unix-socket /var/run/docker.sock -s http://localhost/version 2>/dev/null; curl --unix-socket /var/run/docker.sock -s http://localhost/containers/json 2>/dev/null | jq -c '.[]?'",
        "d": ["Docker daemon API enumeration", "Container listing", "Image metadata extraction", "Exposed socket detection"],
        "tgt": ["docker", "daemon_api", "container_enum", "socket_recon"]
    },
    
    "container-registry-scan": {
        "t": "container",
        "c": "registry_enumeration",
        "u": "crane ls TARGET_REGISTRY/repo 2>/dev/null; crane manifest TARGET_REGISTRY/repo:tag 2>/dev/null | jq -r '.config.digest?'",
        "d": ["Container registry listing", "Image tag enumeration", "Manifest/layer inspection", "Public registry scanning"],
        "tgt": ["docker_hub", "ecr", "gcr", "acr", "registry_recon"]
    },
    
    "falco-rules-audit": {
        "t": "container",
        "c": "runtime_policy_recon",
        "u": "find /etc/falco -name '*.yaml' -exec grep -H '^rule:\\|^list:\\|^macro:' {} \\; 2>/dev/null | head -50",
        "d": ["Falco rule enumeration", "Runtime policy discovery", "Alert condition mapping", "Syscall monitoring config"],
        "tgt": ["kubernetes", "runtime_security", "policy_recon", "detection_rules"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔁 CI/CD PIPELINE RECON
    # ─────────────────────────────────────────────────────────────
    "github-recon": {
        "t": "cicd",
        "c": "github_asset_enumeration",
        "u": "curl -H 'Authorization: token (SECRET:github)' -s https://api.github.com/orgs/ORG/repos 2>/dev/null | jq -r '.[].name?'",
        "d": ["Repository enumeration", "Workflow file discovery", "Branch/tag listing", "Contributor mapping"],
        "tgt": ["github", "gitlab", "bitbucket", "repo_enum", "workflow_discovery"],
        "note": "(SECRET:github) injected at runtime; public repos work without auth"
    },
    
    "gitlab-recon": {
        "t": "cicd",
        "c": "gitlab_pipeline_enum",
        "u": "curl --header 'PRIVATE-TOKEN: (SECRET:gitlab)' -s https://gitlab.example.com/api/v4/projects 2>/dev/null | jq -r '.[].path?'",
        "d": ["Project enumeration", "CI/CD pipeline discovery", "Runner configuration mapping", "Variable enumeration"],
        "tgt": ["gitlab", "ci_cd", "pipeline_recon", "runner_enum"],
        "note": "(SECRET:gitlab) injected at runtime"
    },
    
    "jenkins-recon": {
        "t": "cicd",
        "c": "jenkins_instance_enum",
        "u": "curl -s http://TARGET:8080/api/json 2>/dev/null | jq -r '.jobs[]?.name?'",
        "d": ["Jenkins job enumeration", "Build history discovery", "Plugin version mapping", "Node/agent listing"],
        "tgt": ["jenkins", "ci_cd", "build_server", "plugin_enum"]
    },
    
    "circleci-recon": {
        "t": "cicd",
        "c": "circleci_pipeline_discovery",
        "u": "curl -H 'Circle-Token: (SECRET:circleci)' -s https://circleci.com/api/v2/project/gh/ORG/REPO/pipeline 2>/dev/null | jq -r '.items[]?.id?'",
        "d": ["Pipeline enumeration", "Workflow/job mapping", "Context/variable discovery", "Executor type identification"],
        "tgt": ["circleci", "ci_cd", "pipeline_recon", "workflow_enum"],
        "note": "(SECRET:circleci) injected at runtime"
    },
    
    "github-actions-audit": {
        "t": "cicd",
        "c": "workflow_security_recon",
        "u": "echo '(MANIFEST:workflows)' | grep -E 'uses:|env:|secrets:' - 2>/dev/null | sort -u",
        "d": ["GitHub Actions workflow analysis", "Third-party action enumeration", "Environment variable discovery", "Secret usage mapping"],
        "tgt": ["github_actions", "workflow_audit", "action_enum", "permission_recon"],
        "note": "(MANIFEST:workflows) piped via stdin; grep reads from -"
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 DNS/CDN/WAF INFRASTRUCTURE RECON
    # ─────────────────────────────────────────────────────────────
    "dnsrecon-infra": {
        "t": "dns",
        "c": "infrastructure_dns_enum",
        "u": "dnsrecon -d TARGET -t axfr,std,brt,srv -j - 2>/dev/null | jq -r '.[]?.target?'",
        "d": ["Zone transfer testing", "SRV record enumeration", "Mail server discovery", "Brute subdomain discovery"],
        "tgt": ["dns_infra", "zone_transfer", "srv_records", "ns_enum"],
        "note": "-j - outputs JSON to stdout instead of file"
    },
    
    "cdn-fingerprint": {
        "t": "cdn",
        "c": "cdn_waf_detection",
        "u": "echo '(WORDLIST:targets)' | httpx -silent -cdn -waf -json 2>/dev/null | jq -c '.[]?'",
        "d": ["CDN provider detection", "WAF identification", "Edge location mapping", "Origin IP inference"],
        "tgt": ["cdn", "waf", "edge_infra", "origin_discovery"],
        "note": "(WORDLIST:targets) piped via stdin; -l flag removed"
    },
    
    "wafw00f-infra": {
        "t": "waf",
        "c": "waf_fingerprinting",
        "u": "wafw00f -a -v http://TARGET 2>/dev/null | grep -E '^\\[\\*\\]|^\\[\\+\\]'",
        "d": ["WAF product identification", "Vendor/version detection", "Protection mechanism mapping"],
        "tgt": ["waf", "security_infra", "protection_enum", "vendor_id"]
    },
    
    "shodan-infra": {
        "t": "passive",
        "c": "infrastructure_intelligence",
        "u": "shodan search 'org:\"TARGET_ORG\"' --fields ip,port,hostnames,org 2>/dev/null",
        "d": ["Internet-wide asset discovery", "Service/version enumeration", "Geolocation mapping", "Vulnerability tag correlation"],
        "tgt": ["external_infra", "asset_inventory", "service_enum", "vuln_correlation"],
        "note": "Requires SHODAN_API_KEY env var"
    },
    
    "censys-infra": {
        "t": "passive",
        "c": "certificate_service_recon",
        "u": "censys search 'services.tls.certificate.subject.organization: TARGET' --fields ip,services.port 2>/dev/null | jq -c '.[]?'",
        "d": ["Certificate transparency enumeration", "TLS service discovery", "SAN/subject name extraction", "Port/service mapping"],
        "tgt": ["tls_infra", "cert_recon", "service_discovery", "org_mapping"],
        "note": "Requires CENSYS_API_ID and CENSYS_API_SECRET env vars"
    },

    # ─────────────────────────────────────────────────────────────
    # 🗄️ STORAGE INFRASTRUCTURE RECON
    # ─────────────────────────────────────────────────────────────
    "s3-enumerator": {
        "t": "storage",
        "c": "s3_bucket_discovery",
        "u": "echo '(WORDLIST:s3_buckets)' | xargs -I{} aws s3api head-bucket --bucket {} --region us-east-1 2>&1 | grep -E '200|403|404'",
        "d": ["AWS S3 bucket brute-forcing", "Region enumeration", "Permission testing", "Public bucket identification"],
        "tgt": ["aws_s3", "bucket_enum", "storage_recon", "public_assets"],
        "note": "(WORDLIST:s3_buckets) piped via stdin; no -o results.txt"
    },
    
    "gcs-bruter": {
        "t": "storage",
        "c": "gcs_bucket_discovery",
        "u": "echo '(WORDLIST:gcs_perms)' | xargs -I{} gsutil ls -b gs://{} 2>/dev/null | grep -oE 'gs://[a-z0-9._-]+' | sort -u",
        "d": ["GCS bucket name permutation testing", "Project association mapping", "Public bucket identification"],
        "tgt": ["gcp_storage", "gcs_buckets", "bucket_enum", "public_recon"],
        "note": "(WORDLIST:gcs_perms) piped via stdin; no temp files"
    },
    
    "nfs-enum": {
        "t": "storage",
        "c": "nfs_share_discovery",
        "u": "showmount -e TARGET_IP 2>/dev/null; rpcinfo -p TARGET_IP 2>/dev/null | grep nfs",
        "d": ["NFS export listing", "Mount point enumeration", "Permission mapping", "RPC service verification"],
        "tgt": ["nfs", "file_shares", "unix_storage", "network_enum"]
    },
    
    "smb-share-enum": {
        "t": "storage",
        "c": "smb_share_discovery",
        "u": "smbclient -L //TARGET_IP -N 2>/dev/null | grep -E 'Disk|Share'",
        "d": ["SMB share enumeration", "Null session testing", "Share permission discovery", "Guest access verification"],
        "tgt": ["smb", "windows_shares", "file_server", "share_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # ⚡ SERVERLESS & FUNCTION RECON
    # ─────────────────────────────────────────────────────────────
    "serverless-recon": {
        "t": "serverless",
        "c": "function_enumeration",
        "u": "aws lambda list-functions --query 'Functions[*].FunctionName' --output text 2>/dev/null",
        "d": ["Lambda/Azure Function/GCF listing", "Runtime/environment discovery", "Trigger mapping", "Version/alias discovery"],
        "tgt": ["aws_lambda", "azure_functions", "gcp_cloud_functions", "faas_recon"]
    },
    
    "apigateway-enum": {
        "t": "serverless",
        "c": "api_gateway_discovery",
        "u": "aws apigateway get-rest-apis --query 'items[*].[name,id]]' --output text 2>/dev/null",
        "d": ["API Gateway REST API enumeration", "Stage/deployment mapping", "Endpoint URL extraction"],
        "tgt": ["aws_apigateway", "serverless_apis", "gateway_recon", "endpoint_enum"]
    },
    
    "cloudfunction-perm-check": {
        "t": "serverless",
        "c": "function_permission_audit",
        "u": "gcloud functions describe FUNCTION_NAME --region REGION --format='value(entryPoint,availableMemoryMb,timeout)' 2>/dev/null",
        "d": ["Cloud Function configuration inspection", "Trigger event mapping", "Memory/timeout settings", "IAM binding discovery"],
        "tgt": ["gcp_functions", "permission_recon", "config_audit", "trigger_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📦 INFRASTRUCTURE-AS-CODE RECON
    # ─────────────────────────────────────────────────────────────
    "terraform-state-audit": {
        "t": "iac",
        "c": "tf_state_enumeration",
        "u": "echo '(MANIFEST:tfstate)' | terraform show -json - 2>/dev/null | jq -r '.resources[]?.type?'",
        "d": ["Terraform resource enumeration", "Provider/module discovery", "Output variable mapping", "Backend configuration inspection"],
        "tgt": ["terraform", "iac_recon", "state_audit", "resource_enum"],
        "note": "(MANIFEST:tfstate) piped via stdin; terraform reads from -"
    },
    
    "cloudformation-lint-recon": {
        "t": "iac",
        "c": "cfn_template_analysis",
        "u": "echo '(MANIFEST:cfn)' | cfn-lint - --info 2>/dev/null | grep -E 'resource|parameter|output'",
        "d": ["CloudFormation template parsing", "Resource type enumeration", "Parameter/Output mapping", "IAM policy discovery"],
        "tgt": ["cloudformation", "aws_iac", "template_recon", "resource_mapping"],
        "note": "(MANIFEST:cfn) piped via stdin; cfn-lint reads from -"
    },
    
    "pulumi-stack-inspect": {
        "t": "iac",
        "c": "pulumi_state_recon",
        "u": "pulumi stack --show-secrets=false --json 2>/dev/null | jq -r '.[]?.stack?'",
        "d": ["Pulumi stack enumeration", "Resource summary extraction", "Configuration variable names", "Provider/plugin version mapping"],
        "tgt": ["pulumi", "iac_recon", "stack_enum", "multi_cloud_iac"]
    },
    
    "ansible-inventory-audit": {
        "t": "iac",
        "c": "ansible_host_enum",
        "u": "ansible-inventory --list -i (CONFIG:ansible_inventory) --output json 2>/dev/null | jq 'keys'",
        "d": ["Ansible host/group enumeration", "Variable name discovery", "Role/module usage mapping", "Connection method identification"],
        "tgt": ["ansible", "config_management", "host_inventory", "automation_recon"],
        "note": "(CONFIG:ansible_inventory) resolves to default or injected path"
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 MONITORING & LOGGING INFRA RECON
    # ─────────────────────────────────────────────────────────────
    "prometheus-metrics-enum": {
        "t": "monitoring",
        "c": "prometheus_endpoint_discovery",
        "u": "curl -s http://TARGET:9090/api/v1/label/__name__/values 2>/dev/null | jq -r '.data[]?'",
        "d": ["Prometheus metric name enumeration", "Target/instance discovery", "Job label mapping", "Alert rule discovery"],
        "tgt": ["prometheus", "metrics_recon", "monitoring_enum", "observability"]
    },
    
    "grafana-datasource-recon": {
        "t": "monitoring",
        "c": "grafana_config_discovery",
        "u": "curl -s -H 'Authorization: Bearer (SECRET:grafana)' http://TARGET:3000/api/datasources 2>/dev/null | jq -r '.[].type?'",
        "d": ["Grafana datasource enumeration", "Backend service mapping", "Dashboard listing", "User/role discovery"],
        "tgt": ["grafana", "dashboard_recon", "datasource_enum", "observability"],
        "note": "(SECRET:grafana) injected at runtime"
    },
    
    "elasticsearch-enum": {
        "t": "logging",
        "c": "es_cluster_discovery",
        "u": "curl -s http://TARGET:9200/_cat/nodes?v 2>/dev/null; curl -s http://TARGET:9200/_cat/indices?v 2>/dev/null",
        "d": ["Elasticsearch node enumeration", "Index listing", "Shard/replica mapping", "Cluster health/status"],
        "tgt": ["elasticsearch", "logging_infra", "cluster_recon", "index_enum"]
    },
    
    "splunk-recon": {
        "t": "logging",
        "c": "splunk_instance_enum",
        "u": "curl -k -s https://TARGET:8089/services/server/info?output_mode=json 2>/dev/null | jq -r '.entry[0]?.content?.version?'",
        "d": ["Splunk management port enumeration", "Version/build discovery", "License/type identification", "App/add-on listing"],
        "tgt": ["splunk", "siem_recon", "logging_infra", "management_api"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 NETWORK INFRASTRUCTURE RECON (Routers/Switches/Firewalls)
    # ─────────────────────────────────────────────────────────────
    "snmp-infra-enum": {
        "t": "network",
        "c": "snmp_device_discovery",
        "u": "snmpwalk -v2c -c (SECRET:snmp_community) TARGET_IP 1.3.6.1.2.1.1 2>/dev/null | grep -E 'sysName|sysDescr|sysLocation'",
        "d": ["SNMP v2c community query", "Device name/model/location extraction", "Interface enumeration", "Routing table discovery"],
        "tgt": ["network_devices", "snmp_recon", "cisco", "juniper", "arista"],
        "note": "(SECRET:snmp_community) defaults to 'public' if not injected"
    },
    
    "cisco-recon": {
        "t": "network",
        "c": "cisco_device_enum",
        "u": "nmap -sV --script cisco-* -Pn TARGET_IP 2>/dev/null | grep -E 'script|version'",
        "d": ["Cisco device version detection", "IOS/IOS-XE/NX-OS identification", "SNMP/SSH/Telnet service mapping", "CVE correlation"],
        "tgt": ["cisco", "network_devices", "ios_enum", "switch_recon"]
    },
    
    "firewall-rule-audit": {
        "t": "network",
        "c": "firewall_config_recon",
        "u": "curl -k -s 'https://TARGET/api/?key=(SECRET:fw_api_key)&action=show&type=config' 2>/dev/null | jq -r '.response?.result?.devices?.entry[]?.name?'",
        "d": ["Firewall rule enumeration", "Zone/interface mapping", "NAT policy discovery", "Object group listing"],
        "tgt": ["palo_alto", "fortinet", "checkpoint", "firewall_recon"],
        "note": "(SECRET:fw_api_key) injected at runtime; API access required"
    },
    
    "lldp-discovery": {
        "t": "network",
        "c": "layer2_neighbor_enum",
        "u": "timeout 10 tcpdump -i eth0 -nn -vv ether[20:2] == 0x88cc 2>/dev/null | grep -E 'Chassis ID|Port ID|System Name'",
        "d": ["LLDP packet capture", "Neighbor device discovery", "Port/interface mapping", "Network topology inference"],
        "tgt": ["layer2", "switch_enum", "topology_recon", "neighbor_discovery"],
        "note": "Requires root/cap_net_raw; timeout prevents hanging"
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "infra-recon-pipeline": {
        "t": "automation",
        "c": "multi_cloud_toolchain",
        "u": "# Chain via pipes: cloud_enum -k TARGET | httpx -silent | kube-hunter --remote {} --report json",
        "d": ["Cross-cloud asset discovery chaining", "Deduplication across sources", "JSON output to stdout"],
        "tgt": ["multi_cloud", "scalable_recon", "enterprise_discovery", "bug_bounty"]
    },
    
    "docker-infra-recon": {
        "t": "automation",
        "c": "containerized_toolchain",
        "u": "echo '(WORDLIST:targets)' | docker run --rm -i ghcr.io/projectdiscovery/httpx:latest -silent -cdn -waf -json 2>/dev/null | jq -c '.[]?'",
        "d": ["Reproducible infra recon environments", "Version-pinned tools", "JSON output to stdout"],
        "tgt": ["all", "lab", "client_deliverables", "compliance_audits"],
        "note": "(WORDLIST:targets) piped via stdin; -l flag removed"
    },
    
    "custom-infra-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your script: Parse cloud APIs → Correlate assets → Output JSON to stdout",
        "d": ["Custom cloud API integrations", "Asset correlation logic", "Topology graph generation", "Structured JSON output"],
        "tgt": ["enterprise", "red_team", "compliance", "client_specific"]
    },
    "zap-cli": {
    "t": "scanner",
    "c": "api_security_scan",
    "u": "zap-cli openapi-scan -o - -t http://TARGET/swagger.json 2>/dev/null | jq -r '.alerts[]?.name?'",
    "d": ["OpenAPI/Swagger import", "API-specific rule scanning", "auth flow testing", "JSON output to stdout"],
    "tgt": ["api", "openapi", "soap", "auth_testing", "misconfigs"],
    "note": "Requires ZAP daemon running: zap-cli start --daemon"
},
"john": {
    "t": "password_crack",
    "c": "offline_hash_cracking",
    "u": "echo '(MANIFEST:hashes)' | john --format=auto --wordlist=(WORDLIST:passwords) --stdout --pot=none - 2>/dev/null | grep -v '^Using'",
    "d": [
        "offline password hash cracking",
        "auto-format detection (NTLM, SHA, bcrypt, etc.)",
        "wordlist + rule-based attacks",
        "cracked passwords to stdout",
        "no .pot file writes (--pot=none)"
    ],
    "tgt": [
        "ntlm", "kerberos", "sha1", "sha256", "sha512", "bcrypt", 
        "md5", "ssh_keys", "zip", "pdf", "local_accounts", 
        "dumped_credentials", "hash_cracking", "post_exploitation"
    ],
    "note": "(MANIFEST:hashes) piped via stdin in John format (user:hash); (WORDLIST:passwords) resolved at runtime; --stdout outputs cracked creds; --pot=none avoids file writes",
    "alt": "john --format=nt --wordlist=(WORDLIST:passwords) --stdout --pot=none - 2>/dev/null"
    },
    "hydra": {
    "t": "auth_bruteforce",
    "c": "online_password_spray",
    "u": "hydra -L (WORDLIST:users) -P (WORDLIST:passwords) -t 4 -f TARGET SERVICE 2>/dev/null",
    "d": [
        "online credential brute-forcing",
        "protocol-aware authentication testing",
        "parallel connection handling",
        "early exit on first success",
        "stdout results for chaining"
    ],
    "tgt": [
        "ssh", "ftp", "http", "https", "smb", "rdp", 
        "mysql", "postgres", "ldap", "smtp", "pop3", 
        "active_directory", "network_services", "auth_testing"
    ],
    "note": "(WORDLIST:users) and (WORDLIST:passwords) resolved at runtime; SERVICE = ssh/ftp/http/etc.",
    "alt": "hydra -l user -P (WORDLIST:passwords) -t 4 -f TARGET SERVICE 2>/dev/null"
    },
}

INFRA_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_INFRA_RECON_TOOLS)

infra_tools = INFRA_RECON_TOOLS
