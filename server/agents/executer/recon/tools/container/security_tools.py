"""Curated container recon security tool catalog for `run_custom` usage."""
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
        "d": ["Container listing (running/stopped)", "Image inventory", "Network/volume discovery", "Port mapping enumeration"],
        "tgt": ["docker_host", "local_containers", "image_recon"]
    },
    
    "docker-socket-enum": {
        "t": "docker",
        "c": "api_endpoint_discovery",
        "u": "curl --unix-socket /var/run/docker.sock -s http://localhost/version; curl --unix-socket /var/run/docker.sock -s http://localhost/containers/json | jq -c '.[]'",
        "d": ["Docker API version detection", "Container enumeration via API", "Image metadata extraction", "Exposed socket discovery"],
        "tgt": ["docker_socket", "api_recon", "exposed_daemon"]
    },
    
    "ctop": {
        "t": "docker",
        "c": "runtime_monitoring",
        "u": "ctop -a 2>&1 | head -50",
        "d": ["Real-time container metrics snapshot", "CPU/memory usage mapping", "Network I/O discovery", "Process enumeration"],
        "tgt": ["docker_host", "runtime_recon", "resource_mapping"],
        "note": "Interactive by default; use head/tail for stream output"
    },
    
    "dive": {
        "t": "docker",
        "c": "image_layer_analysis",
        "u": "dive TARGET_IMAGE:TAG --ci --json 2>/dev/null | jq -r '.layers[] | {size, command}'",
        "d": ["Docker image layer inspection", "File change discovery per layer", "Layer content enumeration", "JSON output to stdout"],
        "tgt": ["docker_images", "layer_recon", "image_audit"]
    },
    
    # ─────────────────────────────────────────────────────────────
    # ☸️ KUBERNETES CLUSTER RECON
    # ─────────────────────────────────────────────────────────────
    "kubectl-get-all": {
        "t": "k8s",
        "c": "resource_enumeration",
        "u": "kubectl get all --all-namespaces -o wide --no-headers",
        "d": ["Pod/Service/Deployment listing", "Namespace enumeration", "Node discovery", "Label/selector extraction"],
        "tgt": ["k8s_cluster", "resource_inventory", "namespace_enum"]
    },
    
    "kubectl-describe": {
        "t": "k8s",
        "c": "detailed_resource_inspection",
        "u": "kubectl describe pod POD_NAME -n NAMESPACE 2>/dev/null | grep -E 'Image:|Environment:|Mounts:'",
        "d": ["Container spec inspection", "Environment variable discovery", "Volume mount mapping", "Node assignment"],
        "tgt": ["k8s_pods", "config_recon", "spec_audit"]
    },
    
    "k9s": {
        "t": "k8s",
        "c": "interactive_cluster_browser",
        "u": "# Interactive: k9s — use :pods, :deployments, :secrets for navigation",
        "d": ["Interactive K8s resource browser", "Real-time cluster monitoring", "Log streaming", "Quick context switching"],
        "tgt": ["k8s_cluster", "interactive_recon", "live_monitoring"]
    },
    
    "kube-hunter": {
        "t": "k8s",
        "c": "security_recon",
        "u": "kube-hunter --remote K8S_API_IP --report json --log-file none 2>/dev/null | jq -c '.vulnerabilities[]?'",
        "d": ["K8s API server enumeration", "Exposed dashboard detection", "RBAC permission mapping", "CVE correlation (read-only)"],
        "tgt": ["k8s_security", "api_server_recon", "vulnerability_mapping"]
    },
    
    "kubectx": {
        "t": "k8s",
        "c": "context_namespace_switching",
        "u": "kubectx; kubens",
        "d": ["Context enumeration", "Namespace listing", "Quick cluster switching", "Multi-cluster recon support"],
        "tgt": ["k8s_contexts", "namespace_enum", "multi_cluster"]
    },
    
    "trivy-k8s": {
        "t": "k8s",
        "c": "cluster_scanning",
        "u": "trivy k8s --report=summary cluster --format json 2>/dev/null | jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID?'",
        "d": ["K8s manifest scanning", "Misconfiguration detection", "CVE mapping for images", "JSON output to stdout"],
        "tgt": ["k8s_config", "vulnerability_recon", "policy_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📦 CONTAINER REGISTRY RECON
    # ─────────────────────────────────────────────────────────────
    "crane": {
        "t": "registry",
        "c": "registry_enumeration",
        "u": "crane ls TARGET_REGISTRY/repo 2>/dev/null; crane manifest TARGET_REGISTRY/repo:tag 2>/dev/null | jq -r '.config.digest'",
        "d": ["Container registry listing", "Image tag enumeration", "Manifest/layer inspection", "Config extraction"],
        "tgt": ["docker_hub", "ecr", "gcr", "acr", "registry_recon"]
    },
    
    "docker-registry-cli": {
        "t": "registry",
        "c": "api_enumeration",
        "u": "docker-registry-cli -r https://registry.example.com repos list 2>/dev/null | grep -v '^$'",
        "d": ["Registry API enumeration", "Repository listing", "Tag discovery", "Authentication testing"],
        "tgt": ["private_registries", "api_recon", "auth_testing"],
        "note": "Add -u/-p flags via env vars or secret injection at runtime"
    },
    
    "skopeo": {
        "t": "registry",
        "c": "image_inspection",
        "u": "skopeo inspect docker://TARGET_REGISTRY/repo:TAG --format '{{.Digest}}' 2>/dev/null",
        "d": ["Image metadata inspection", "Layer digest enumeration", "OS/architecture discovery", "Multi-arch image support"],
        "tgt": ["container_images", "metadata_recon", "multi_arch"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔍 CONTAINER IMAGE ANALYSIS
    # ─────────────────────────────────────────────────────────────
    "trivy-image": {
        "t": "image",
        "c": "vulnerability_scanning",
        "u": "trivy image TARGET_IMAGE:TAG --severity HIGH,CRITICAL --format json --exit-code 0 2>/dev/null | jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID?'",
        "d": ["OS package vulnerability detection", "Application dependency scanning", "CVE correlation", "JSON output to stdout"],
        "tgt": ["container_images", "vuln_recon", "security_audit"]
    },
    
    "grype": {
        "t": "image",
        "c": "vulnerability_enumeration",
        "u": "grype TARGET_IMAGE:TAG --output json --fail-on high 2>/dev/null | jq -r '.matches[]?.vulnerability?.id?'",
        "d": ["Image vulnerability scanning", "Package enumeration", "CVE/CVSS mapping", "Fix version discovery"],
        "tgt": ["container_images", "vuln_recon", "sbom_generation"]
    },
    
    # ─────────────────────────────────────────────────────────────
    # 🌐 CONTAINER NETWORK RECON
    # ─────────────────────────────────────────────────────────────
    "netshoot": {
        "t": "network",
        "c": "network_debug_container",
        "u": "docker run --rm --net container:TARGET_CONTAINER nicolaka/netshoot netstat -tuln 2>/dev/null",
        "d": ["Network namespace inspection", "Port listening discovery", "Connection enumeration", "DNS resolution testing"],
        "tgt": ["container_network", "port_enum", "connectivity_recon"]
    },
    
    "container-dns-enum": {
        "t": "network",
        "c": "dns_service_discovery",
        "u": "kubectl run dns-test --rm -it --image=nicolaka/netshoot --restart=Never -- nslookup kubernetes.default 2>&1 | grep -A2 'Name:'",
        "d": ["K8s DNS enumeration", "Service name resolution", "Cluster domain discovery", "External DNS mapping"],
        "tgt": ["k8s_dns", "service_discovery", "network_recon"]
    },
    
    "calicoctl": {
        "t": "network",
        "c": "cni_policy_enum",
        "u": "calicoctl get networkpolicies --all-namespaces -o wide 2>/dev/null | grep -v '^NAME'",
        "d": ["Network policy enumeration", "Ingress/egress rule mapping", "Pod selector discovery", "Namespace isolation audit"],
        "tgt": ["k8s_networking", "policy_recon", "cni_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 CONTAINER SECRET & CONFIG RECON
    # ─────────────────────────────────────────────────────────────
    "kubectl-secrets-enum": {
        "t": "secrets",
        "c": "k8s_secret_discovery",
        "u": "kubectl get secrets --all-namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\\n'",
        "d": ["Secret name enumeration", "Type discovery (Opaque/tls/service-account)", "Namespace mapping", "Annotation extraction"],
        "tgt": ["k8s_secrets", "config_recon", "credential_inventory"]
    },
    
    "container-env-dump": {
        "t": "config",
        "c": "environment_variable_enum",
        "u": "docker inspect CONTAINER --format='{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -v '^$'",
        "d": ["Environment variable listing", "ConfigMap/Secret reference discovery", "Sensitive var naming patterns"],
        "tgt": ["container_config", "env_recon", "secret_hunting"]
    },
    
    "kubecapture": {
        "t": "config",
        "c": "resource_capture",
        "u": "kubectl get all -o yaml --export 2>/dev/null | grep -E 'name:|namespace:|image:'",
        "d": ["Cluster resource enumeration", "YAML manifest streaming", "ConfigMap/Secret structure inspection", "RBAC role enumeration"],
        "tgt": ["k8s_config", "manifest_recon", "backup_audit"],
        "note": "--export deprecated in newer K8s; use kubectl get -o yaml | yq for filtering"
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 CONTAINER RUNTIME & LOG RECON
    # ─────────────────────────────────────────────────────────────
    "docker-logs": {
        "t": "logs",
        "c": "container_log_capture",
        "u": "docker logs --tail 100 CONTAINER_ID 2>&1 | grep -iE 'error|warn|api|http|exception'",
        "d": ["Container log enumeration", "Error/warning discovery", "API endpoint leakage", "Stack trace extraction"],
        "tgt": ["container_logs", "debug_recon", "info_leak"]
    },
    
    "kubectl-logs": {
        "t": "logs",
        "c": "pod_log_streaming",
        "u": "kubectl logs POD_NAME -n NAMESPACE --tail=100 --all-containers 2>&1 | grep -iE 'error|warn|fatal'",
        "d": ["Pod log enumeration", "Multi-container log aggregation", "Timestamp correlation", "Error pattern detection"],
        "tgt": ["k8s_logs", "pod_recon", "debug_info"]
    },
    
    "stern": {
        "t": "logs",
        "c": "multi_pod_log_tail",
        "u": "stern '.*' --namespace NAMESPACE --tail 50 --grep 'error|warn' 2>&1 | head -100",
        "d": ["Multi-pod log streaming", "Regex-based filtering", "Container name highlighting", "Real-time log aggregation"],
        "tgt": ["k8s_logs", "multi_pod_recon", "live_monitoring"]
    },
    
    "container-dmesg": {
        "t": "logs",
        "c": "kernel_log_enum",
        "u": "dmesg 2>/dev/null | grep -iE 'docker|container|cgroup|namespace|oom'",
        "d": ["Kernel container events", "Namespace creation logs", "Cgroup activity discovery", "OOM killer events"],
        "tgt": ["host_kernel", "container_events", "runtime_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🛡️ CONTAINER SECURITY CONFIG RECON
    # ─────────────────────────────────────────────────────────────
    "docker-bench": {
        "t": "security",
        "c": "docker_hardening_audit",
        "u": "docker-bench-security.sh 2>&1 | grep -E '^\\[WARN\\]|^\\[INFO\\]'",
        "d": ["Docker daemon config audit", "Container runtime checks", "Image security validation", "Network config inspection"],
        "tgt": ["docker_host", "security_recon", "hardening_audit"]
    },
    
    "kube-bench": {
        "t": "security",
        "c": "k8s_benchmark_scan",
        "u": "kube-bench run --targets node,master,etcd,policies --json 2>/dev/null | jq -r '.Results[]?.failures[]?.test_number?'",
        "d": ["CIS Kubernetes benchmark checks", "Master/node config audit", "Policy validation", "RBAC configuration check"],
        "tgt": ["k8s_cluster", "cis_benchmark", "compliance_recon"]
    },
    
    "polaris": {
        "t": "security",
        "c": "k8s_config_validation",
        "u": "polaris audit --config (CONFIG:polaris) --format json 2>/dev/null | jq -r '.Results[]?.PodResult?.podName?'",
        "d": ["K8s best practice validation", "Resource limit checks", "Security context audit", "Image pull policy verification"],
        "tgt": ["k8s_config", "best_practice_recon", "policy_audit"],
        "note": "(CONFIG:polaris) resolves to default or injected config path"
    },
    
    "datree": {
        "t": "security",
        "c": "k8s_manifest_testing",
        "u": "echo '(MANIFEST:yaml)' | datree test - --rules K8S --output json 2>/dev/null | jq -r '.results[]?.rule?.identifier?'",
        "d": ["K8s manifest validation", "Policy enforcement checks", "Best practice verification", "Misconfiguration detection"],
        "tgt": ["k8s_manifests", "iac_recon", "policy_validation"],
        "note": "(MANIFEST:yaml) is piped via stdin; datree reads from -"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔄 CONTAINER ORCHESTRATION RECON
    # ─────────────────────────────────────────────────────────────
    "nomad-cli": {
        "t": "orchestration",
        "c": "nomad_job_enum",
        "u": "nomad job status 2>/dev/null | grep -v '^ID'; nomad node status 2>/dev/null | head -20",
        "d": ["Job enumeration", "Node/agent discovery", "Allocation mapping", "Datacenter enumeration"],
        "tgt": ["nomad_cluster", "job_recon", "orchestration_enum"]
    },
    
    "swarm-cli": {
        "t": "orchestration",
        "c": "docker_swarm_enum",
        "u": "docker node ls 2>/dev/null; docker service ls 2>/dev/null; docker stack ls 2>/dev/null",
        "d": ["Swarm node enumeration", "Service listing", "Stack discovery", "Network overlay mapping"],
        "tgt": ["docker_swarm", "service_recon", "cluster_enum"]
    },
    
    "mesos-cli": {
        "t": "orchestration",
        "c": "mesos_framework_enum",
        "u": "curl -s http://MESOS_MASTER:5050/master/state.json 2>/dev/null | jq -r '.frameworks[]?.name?'",
        "d": ["Framework enumeration", "Task discovery", "Agent/node mapping", "Resource offer inspection"],
        "tgt": ["mesos_cluster", "framework_recon", "task_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "container-recon-pipeline": {
        "t": "automation",
        "c": "multi_tool_chaining",
        "u": "# Chain via pipes: kubectl get pods -o json | jq -r '.items[].metadata.name' | xargs -I{} trivy image {}",
        "d": ["K8s resource enumeration chaining", "Vulnerability scanning integration", "Security audit automation", "JSON output to stdout"],
        "tgt": ["k8s_cluster", "automated_recon", "continuous_audit"]
    },
    
    "docker-compose-enum": {
        "t": "automation",
        "c": "compose_file_analysis",
        "u": "docker-compose config --services 2>/dev/null; docker-compose ps --services 2>/dev/null",
        "d": ["Service enumeration from compose", "Volume/network mapping", "Environment variable discovery", "Port exposure listing"],
        "tgt": ["docker_compose", "local_recon", "dev_environment"]
    },
    
    "custom-container-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your script: Query Docker/K8s APIs → Generate topology + risk map → Output JSON to stdout",
        "d": ["Custom API integrations", "Asset correlation logic", "Topology graph generation", "Structured output (JSON)"],
        "tgt": ["enterprise", "red_team", "client_specific", "large_clusters"]
    }
}

CONTAINER_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_CONTAINER_RECON_TOOLS)

container_tools = CONTAINER_RECON_TOOLS
