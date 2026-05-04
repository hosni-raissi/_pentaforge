"""Curated container recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_CONTAINER_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🐳 DOCKER DAEMON & CONTAINER ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "docker-cli": {
        "t": "docker",
        "c": "container_image_enum",
        "u": "docker ps -a; docker images; docker network ls; docker volume ls",
        "d": ["Container listing (running/stopped)", "Image inventory", "Network/volume discovery", "Port mapping enumeration", "Environment variable extraction"],
        "tgt": ["docker_host", "local_containers", "image_recon"]
    },
    
    "docker-socket-enum": {
        "t": "docker",
        "c": "api_endpoint_discovery",
        "u": "curl --unix-socket /var/run/docker.sock http://localhost/version; curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
        "d": ["Docker API version detection", "Container enumeration via API", "Image metadata extraction", "Network/volume mapping", "Exposed socket discovery"],
        "tgt": ["docker_socket", "api_recon", "exposed_daemon"]
    },
    
    "ctop": {
        "t": "docker",
        "c": "runtime_monitoring",
        "u": "ctop  # Or: ctop -a for all containers",
        "d": ["Real-time container metrics", "CPU/memory usage mapping", "Network I/O discovery", "Process enumeration inside containers", "Top-like interface for containers"],
        "tgt": ["docker_host", "runtime_recon", "resource_mapping"]
    },
    
    "dive": {
        "t": "docker",
        "c": "image_layer_analysis",
        "u": "dive TARGET_IMAGE:TAG",
        "d": ["Docker image layer inspection", "File change discovery per layer", "Wasted space identification", "Layer content enumeration", "Image efficiency analysis"],
        "tgt": ["docker_images", "layer_recon", "image_audit"]
    },
    
    "whaler": {
        "t": "docker",
        "c": "container_info_enrichment",
        "u": "whaler CONTAINER_ID",
        "d": ["Container metadata enrichment", "Image details extraction", "Port mapping visualization", "Volume mount discovery", "Environment variable listing"],
        "tgt": ["docker_containers", "metadata_enum", "config_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # ☸️ KUBERNETES CLUSTER RECON (Most Used)
    # ─────────────────────────────────────────────────────────────
    "kubectl-get-all": {
        "t": "k8s",
        "c": "resource_enumeration",
        "u": "kubectl get all --all-namespaces -o wide",
        "d": ["Pod/Service/Deployment listing", "Namespace enumeration", "Node discovery", "Resource quota mapping", "Label/selector extraction"],
        "tgt": ["k8s_cluster", "resource_inventory", "namespace_enum"]
    },
    
    "kubectl-describe": {
        "t": "k8s",
        "c": "detailed_resource_inspection",
        "u": "kubectl describe pod POD_NAME -n NAMESPACE",
        "d": ["Container spec inspection", "Environment variable discovery", "Volume mount mapping", "Resource limits/requests", "Node assignment"],
        "tgt": ["k8s_pods", "config_recon", "spec_audit"]
    },
    
    "k9s": {
        "t": "k8s",
        "c": "interactive_cluster_browser",
        "u": "k9s  # Then navigate: :pods, :deployments, :services, :secrets",
        "d": ["Interactive K8s resource browser", "Real-time cluster monitoring", "Log streaming", "Resource relationship mapping", "Quick context switching"],
        "tgt": ["k8s_cluster", "interactive_recon", "live_monitoring"]
    },
    
    "kube-hunter": {
        "t": "k8s",
        "c": "security_recon",
        "u": "kube-hunter --remote K8S_API_IP --report json --log-file none",
        "d": ["K8s API server enumeration", "Exposed dashboard detection", "RBAC permission mapping", "Node/pod discovery", "CVE correlation (read-only)"],
        "tgt": ["k8s_security", "api_server_recon", "vulnerability_mapping"]
    },
    
    "kubectx + kubens": {
        "t": "k8s",
        "c": "context_namespace_switching",
        "u": "kubectx; kubens",
        "d": ["Context enumeration", "Namespace listing", "Quick cluster switching", "Multi-cluster recon support", "Workflow optimization"],
        "tgt": ["k8s_contexts", "namespace_enum", "multi_cluster"]
    },
    
    "kubenscan": {
        "t": "k8s",
        "c": "risk_assessment",
        "u": "kubenscan --namespace default --output report.html",
        "d": ["Pod security context analysis", "Service account privilege mapping", "Network policy enumeration", "Secret exposure detection", "Risk scoring"],
        "tgt": ["k8s_security", "rbac_recon", "compliance_audit"]
    },
    
    "trivy-k8s": {
        "t": "k8s",
        "c": "cluster_scanning",
        "u": "trivy k8s --report=summary cluster",
        "d": ["K8s manifest scanning", "Misconfiguration detection", "CVE mapping for images", "Policy compliance check", "JSON/YAML report output"],
        "tgt": ["k8s_config", "vulnerability_recon", "policy_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📦 CONTAINER REGISTRY RECON (Most Used)
    # ─────────────────────────────────────────────────────────────
    "crane": {
        "t": "registry",
        "c": "registry_enumeration",
        "u": "crane ls TARGET_REGISTRY/repo; crane manifest TARGET_REGISTRY/repo:tag | jq",
        "d": ["Container registry listing", "Image tag enumeration", "Manifest/layer inspection", "Config extraction", "Public/private registry support"],
        "tgt": ["docker_hub", "ecr", "gcr", "acr", "registry_recon"]
    },
    
    "reg": {
        "t": "registry",
        "c": "registry_scanning",
        "u": "reg ls TARGET_REGISTRY/repo; reg manifest TARGET_REGISTRY/repo:tag",
        "d": ["Registry repository listing", "Tag enumeration", "Manifest inspection", "Vulnerability data extraction", "Multi-registry support"],
        "tgt": ["container_registries", "image_enum", "manifest_recon"]
    },
    
    "docker-registry-cli": {
        "t": "registry",
        "c": "api_enumeration",
        "u": "docker-registry-cli -r https://registry.example.com -u user -p pass repos list",
        "d": ["Registry API enumeration", "Repository listing", "Tag discovery", "Blob/layer metadata", "Authentication testing"],
        "tgt": ["private_registries", "api_recon", "auth_testing"]
    },
    
    "skopeo": {
        "t": "registry",
        "c": "image_inspection",
        "u": "skopeo inspect docker://TARGET_REGISTRY/repo:TAG --format '{{.Digest}}'",
        "d": ["Image metadata inspection", "Layer digest enumeration", "OS/architecture discovery", "Created/timestamp mapping", "Multi-arch image support"],
        "tgt": ["container_images", "metadata_recon", "multi_arch"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔍 CONTAINER IMAGE ANALYSIS (Most Used)
    # ─────────────────────────────────────────────────────────────
    "trivy-image": {
        "t": "image",
        "c": "vulnerability_scanning",
        "u": "trivy image TARGET_IMAGE:TAG --severity HIGH,CRITICAL --format json",
        "d": ["OS package vulnerability detection", "Application dependency scanning", "CVE correlation", "Secret detection", "Misconfiguration audit"],
        "tgt": ["container_images", "vuln_recon", "security_audit"]
    },
    
    "grype": {
        "t": "image",
        "c": "vulnerability_enumeration",
        "u": "grype TARGET_IMAGE:TAG --output json",
        "d": ["Image vulnerability scanning", "Package enumeration", "CVE/CVSS mapping", "Fix version discovery", "SBOM generation"],
        "tgt": ["container_images", "vuln_recon", "sbom_generation"]
    },
    
    "clair": {
        "t": "image",
        "c": "static_analysis",
        "u": "clair-scanner -c clair.yaml --ip YOUR_IP TARGET_IMAGE:TAG",
        "d": ["Image layer analysis", "Vulnerability database correlation", "Feature/app detection", "CVE mapping", "Policy evaluation"],
        "tgt": ["container_images", "static_analysis", "vuln_db_correlation"]
    },
    
    "dive": {
        "t": "image",
        "c": "layer_exploration",
        "u": "dive TARGET_IMAGE:TAG --ci",
        "d": ["Image layer content inspection", "File change discovery", "Efficiency scoring", "Wasted bytes detection", "Layer-by-layer analysis"],
        "tgt": ["docker_images", "layer_recon", "optimization_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 CONTAINER NETWORK RECON (Most Used)
    # ─────────────────────────────────────────────────────────────
    "netshoot": {
        "t": "network",
        "c": "network_debug_container",
        "u": "docker run --net container:TARGET_CONTAINER nicolaka/netshoot netstat -tuln",
        "d": ["Network namespace inspection", "Port listening discovery", "Connection enumeration", "DNS resolution testing", "Traceroute/ping from container"],
        "tgt": ["container_network", "port_enum", "connectivity_recon"]
    },
    
    "container-dns-enum": {
        "t": "network",
        "c": "dns_service_discovery",
        "u": "kubectl run dns-test --rm -it --image=nicolaka/netshoot -- nslookup kubernetes.default",
        "d": ["K8s DNS enumeration", "Service name resolution", "CoreDNS configuration inspection", "Cluster domain discovery", "External DNS mapping"],
        "tgt": ["k8s_dns", "service_discovery", "network_recon"]
    },
    
    "calicoctl": {
        "t": "network",
        "c": "cni_policy_enum",
        "u": "calicoctl get networkpolicies --all-namespaces -o wide",
        "d": ["Network policy enumeration", "Ingress/egress rule mapping", "Pod selector discovery", "Namespace isolation audit", "CNI config inspection"],
        "tgt": ["k8s_networking", "policy_recon", "cni_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 CONTAINER SECRET & CONFIG RECON (Most Used)
    # ─────────────────────────────────────────────────────────────
    "kubectl-secrets-enum": {
        "t": "secrets",
        "c": "k8s_secret_discovery",
        "u": "kubectl get secrets --all-namespaces -o jsonpath='{.items[*].metadata.name}'",
        "d": ["Secret name enumeration", "Type discovery (Opaque/tls/service-account)", "Namespace mapping", "Annotation/label extraction", "Creation timestamp mapping"],
        "tgt": ["k8s_secrets", "config_recon", "credential_inventory"]
    },
    
    "container-env-dump": {
        "t": "config",
        "c": "environment_variable_enum",
        "u": "docker inspect CONTAINER --format='{{range .Config.Env}}{{println .}}{{end}}'",
        "d": ["Environment variable listing", "ConfigMap/Secret reference discovery", "Default value detection", "Sensitive var naming patterns", "Inheritance mapping"],
        "tgt": ["container_config", "env_recon", "secret_hunting"]
    },
    
    "kubecapture": {
        "t": "config",
        "c": "resource_capture",
        "u": "kubectl get all -o yaml --export > cluster_resources.yaml",
        "d": ["Full cluster resource export", "YAML manifest capture", "ConfigMap/Secret structure inspection", "Service account mapping", "RBAC role enumeration"],
        "tgt": ["k8s_config", "manifest_recon", "backup_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 CONTAINER RUNTIME & LOG RECON (Most Used)
    # ─────────────────────────────────────────────────────────────
    "docker-logs": {
        "t": "logs",
        "c": "container_log_capture",
        "u": "docker logs --tail 100 CONTAINER_ID 2>&1 | grep -iE 'error|warn|api|http'",
        "d": ["Container log enumeration", "Error/warning discovery", "API endpoint leakage", "Stack trace extraction", "Startup sequence analysis"],
        "tgt": ["container_logs", "debug_recon", "info_leak"]
    },
    
    "kubectl-logs": {
        "t": "logs",
        "c": "pod_log_streaming",
        "u": "kubectl logs POD_NAME -n NAMESPACE --tail=100 --all-containers",
        "d": ["Pod log enumeration", "Multi-container log aggregation", "Previous instance logs", "Timestamp correlation", "Error pattern detection"],
        "tgt": ["k8s_logs", "pod_recon", "debug_info"]
    },
    
    "stern": {
        "t": "logs",
        "c": "multi_pod_log_tail",
        "u": "stern '.*' --namespace NAMESPACE --tail 50 --grep 'error|warn'",
        "d": ["Multi-pod log streaming", "Regex-based filtering", "Container name highlighting", "Timestamp alignment", "Real-time log aggregation"],
        "tgt": ["k8s_logs", "multi_pod_recon", "live_monitoring"]
    },
    
    "container-dmesg": {
        "t": "logs",
        "c": "kernel_log_enum",
        "u": "dmesg | grep -iE 'docker|container|cgroup|namespace'",
        "d": ["Kernel container events", "Namespace creation logs", "Cgroup activity discovery", "OOM killer events", "Security module alerts"],
        "tgt": ["host_kernel", "container_events", "runtime_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🛡️ CONTAINER SECURITY CONFIG RECON (Most Used)
    # ─────────────────────────────────────────────────────────────
    "docker-bench": {
        "t": "security",
        "c": "docker_hardening_audit",
        "u": "docker-bench-security.sh 2>/dev/null | grep -E 'WARN|INFO'",
        "d": ["Docker daemon config audit", "Container runtime checks", "Image security validation", "Network config inspection", "Logging config verification"],
        "tgt": ["docker_host", "security_recon", "hardening_audit"]
    },
    
    "kube-bench": {
        "t": "security",
        "c": "k8s_benchmark_scan",
        "u": "kube-bench run --targets node,master,etcd,policies --json",
        "d": ["CIS Kubernetes benchmark checks", "Master/node config audit", "Policy validation", "RBAC configuration check", "Remediation guidance"],
        "tgt": ["k8s_cluster", "cis_benchmark", "compliance_recon"]
    },
    
    "polaris": {
        "t": "security",
        "c": "k8s_config_validation",
        "u": "polaris audit --config polaris.yaml --format json",
        "d": ["K8s best practice validation", "Resource limit checks", "Security context audit", "Image pull policy verification", "Health check validation"],
        "tgt": ["k8s_config", "best_practice_recon", "policy_audit"]
    },
    
    "datree": {
        "t": "security",
        "c": "k8s_manifest_testing",
        "u": "datree test manifest.yaml --rules K8S",
        "d": ["K8s manifest validation", "Policy enforcement checks", "Best practice verification", "Misconfiguration detection", "CI/CD integration"],
        "tgt": ["k8s_manifests", "iac_recon", "policy_validation"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔄 CONTAINER ORCHESTRATION RECON (Most Used)
    # ─────────────────────────────────────────────────────────────
    "nomad-cli": {
        "t": "orchestration",
        "c": "nomad_job_enum",
        "u": "nomad job status; nomad node status; nomad alloc status",
        "d": ["Job enumeration", "Node/agent discovery", "Allocation mapping", "Task group inspection", "Datacenter enumeration"],
        "tgt": ["nomad_cluster", "job_recon", "orchestration_enum"]
    },
    
    "swarm-cli": {
        "t": "orchestration",
        "c": "docker_swarm_enum",
        "u": "docker node ls; docker service ls; docker stack ls",
        "d": ["Swarm node enumeration", "Service listing", "Stack discovery", "Network overlay mapping", "Secret/config inspection"],
        "tgt": ["docker_swarm", "service_recon", "cluster_enum"]
    },
    
    "mesos-cli": {
        "t": "orchestration",
        "c": "mesos_framework_enum",
        "u": "curl -s http://MESOS_MASTER:5050/master/state.json | jq '.frameworks[].name'",
        "d": ["Framework enumeration", "Task discovery", "Agent/node mapping", "Resource offer inspection", "Executor enumeration"],
        "tgt": ["mesos_cluster", "framework_recon", "task_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION (Most Used)
    # ─────────────────────────────────────────────────────────────
    "container-recon-pipeline": {
        "t": "automation",
        "c": "multi_tool_chaining",
        "u": "# Your script: kubectl get all | trivy k8s | kube-hunter | kubenscan",
        "d": ["K8s resource enumeration chaining", "Vulnerability scanning integration", "Security audit automation", "Report aggregation", "CI/CD pipeline embedding"],
        "tgt": ["k8s_cluster", "automated_recon", "continuous_audit"]
    },
    
    "docker-compose-enum": {
        "t": "automation",
        "c": "compose_file_analysis",
        "u": "docker-compose config --services; docker-compose ps",
        "d": ["Service enumeration from compose", "Volume/network mapping", "Environment variable discovery", "Port exposure listing", "Dependency graph extraction"],
        "tgt": ["docker_compose", "local_recon", "dev_environment"]
    },
    
    "custom-container-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your Python/Go script: Query Docker/K8s APIs → Generate topology + risk map",
        "d": ["Custom API integrations", "Asset correlation logic", "Topology graph generation", "Risk scoring based on exposure", "Structured output (JSON/GraphML)"],
        "tgt": ["enterprise", "red_team", "client_specific", "large_clusters"]
    }
}

CONTAINER_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_CONTAINER_RECON_TOOLS)

network_tools = CONTAINER_RECON_TOOLS
