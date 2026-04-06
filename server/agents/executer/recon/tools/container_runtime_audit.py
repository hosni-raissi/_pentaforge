import subprocess
import json
import re
import time
import socket
import os
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class ContainerRuntimeAuditRequest(BaseModel):
    tool: str
    target: str = "local"
    args: list[str] = []
    timeout: int = Field(default=1800, ge=30, le=7200)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {
            "docker-bench-security",
            "kube-bench",
            "kube-hunter",
            "kubeaudit",
            "custom"
        }
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous character '{d}' in target")
        return v.strip() or "local"

    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        blocked_flags = ["-o", "--output", "--report", "--file", "--log-path"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked file output flag: {arg}")
        return v


class RuntimeFinding(BaseModel):
    category: str
    title: str
    severity: str = "info"   # critical, high, medium, low, info
    status: str = "info"     # fail, warning, pass, info
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    namespace: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


class RuntimeResourceSummary(BaseModel):
    resource_type: str
    count: int = 0


class ContainerRuntimeAuditResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_findings: int = 0
    severity_summary: dict[str, int] = {}
    resource_summary: list[RuntimeResourceSummary] = []
    findings: list[RuntimeFinding] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 1800) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except PermissionError:
        return "", f"Permission denied running '{cmd[0]}'", -1
    except Exception as e:
        return "", str(e), -1


def command_exists(name: str) -> bool:
    _, _, rc = safe_execute(["which", name], timeout=10)
    return rc == 0


def add_finding(findings: list[RuntimeFinding], resource_counts: dict[str, int], finding: RuntimeFinding):
    findings.append(finding)
    if finding.resource_type:
        resource_counts[finding.resource_type] = resource_counts.get(finding.resource_type, 0) + 1


# ══════════════════════════════════════════════════════════════
# 3. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_docker_bench_output(stdout: str, stderr: str) -> tuple[list[RuntimeFinding], list[RuntimeResourceSummary]]:
    findings = []
    resource_counts: dict[str, int] = {}

    raw = stdout or stderr
    if not raw.strip():
        return findings, []

    for line in raw.splitlines():
        l = line.strip()

        if l.startswith("[WARN]"):
            add_finding(findings, resource_counts, RuntimeFinding(
                category="docker",
                title="Docker Bench warning",
                severity="medium",
                status="warning",
                resource_type="docker_host",
                resource_name="local",
                evidence=l[:2000],
                recommendation="Review Docker Bench warning and apply recommended hardening"
            ))
        elif l.startswith("[NOTE]"):
            add_finding(findings, resource_counts, RuntimeFinding(
                category="docker",
                title="Docker Bench note",
                severity="low",
                status="info",
                resource_type="docker_host",
                resource_name="local",
                evidence=l[:2000],
            ))
        elif l.startswith("[INFO]"):
            continue
        elif l.startswith("[PASS]"):
            add_finding(findings, resource_counts, RuntimeFinding(
                category="docker",
                title="Docker Bench passed check",
                severity="info",
                status="pass",
                resource_type="docker_host",
                resource_name="local",
                evidence=l[:500],
            ))

    return findings, [RuntimeResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]


def parse_kube_bench_output(stdout: str, stderr: str) -> tuple[list[RuntimeFinding], list[RuntimeResourceSummary]]:
    findings = []
    resource_counts: dict[str, int] = {}
    raw = stdout or stderr
    if not raw.strip():
        return findings, []

    # try json first
    try:
        data = json.loads(raw)
        # generic recursive parsing
        if isinstance(data, dict):
            controls = data.get("Controls") or data.get("controls") or []
            for control in controls:
                tests = control.get("tests", []) or control.get("Tests", [])
                for test in tests:
                    results = test.get("results", []) or test.get("Results", [])
                    for res in results:
                        status = str(res.get("status", res.get("Status", "INFO"))).upper()
                        desc = res.get("test_desc") or res.get("desc") or res.get("test_number") or "kube-bench finding"
                        evidence = res.get("audit") or res.get("Audit") or res.get("reason")
                        severity = "info"
                        final_status = "info"
                        if status == "FAIL":
                            severity = "high"
                            final_status = "fail"
                        elif status == "WARN":
                            severity = "medium"
                            final_status = "warning"
                        elif status == "PASS":
                            final_status = "pass"

                        add_finding(findings, resource_counts, RuntimeFinding(
                            category="kubernetes",
                            title=str(desc),
                            severity=severity,
                            status=final_status,
                            resource_type="k8s_control",
                            resource_name=res.get("test_number") or res.get("TestNum"),
                            evidence=str(evidence)[:2000] if evidence else None,
                            recommendation=res.get("remediation") or res.get("Remediation"),
                        ))
        if findings:
            return findings, [RuntimeResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]
    except Exception:
        pass

    # text fallback
    for line in raw.splitlines():
        l = line.strip()
        if l.startswith("[FAIL]"):
            add_finding(findings, resource_counts, RuntimeFinding(
                category="kubernetes",
                title="kube-bench failed check",
                severity="high",
                status="fail",
                resource_type="k8s_control",
                evidence=l[:2000],
                recommendation="Apply CIS Kubernetes benchmark remediation"
            ))
        elif l.startswith("[WARN]"):
            add_finding(findings, resource_counts, RuntimeFinding(
                category="kubernetes",
                title="kube-bench warning",
                severity="medium",
                status="warning",
                resource_type="k8s_control",
                evidence=l[:2000],
            ))
        elif l.startswith("[PASS]"):
            add_finding(findings, resource_counts, RuntimeFinding(
                category="kubernetes",
                title="kube-bench passed check",
                severity="info",
                status="pass",
                resource_type="k8s_control",
                evidence=l[:500],
            ))

    return findings, [RuntimeResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]


def parse_kube_hunter_output(stdout: str, stderr: str) -> tuple[list[RuntimeFinding], list[RuntimeResourceSummary]]:
    findings = []
    resource_counts: dict[str, int] = {}
    raw = stdout or stderr

    if not raw.strip():
        return findings, []

    # json first
    try:
        data = json.loads(raw)
        items = data.get("nodes", []) or data.get("services", []) or data.get("vulnerabilities", []) or []

        def walk(obj):
            if isinstance(obj, dict):
                title = obj.get("vulnerability") or obj.get("location") or obj.get("type")
                severity = str(obj.get("severity", "medium")).lower()
                if title:
                    add_finding(findings, resource_counts, RuntimeFinding(
                        category="kubernetes",
                        title=str(title),
                        severity=severity if severity in {"critical", "high", "medium", "low", "info"} else "medium",
                        status="warning",
                        resource_type="k8s_exposure",
                        resource_name=obj.get("location"),
                        evidence=json.dumps(obj)[:2000],
                        recommendation="Restrict exposed Kubernetes services and follow kube-hunter guidance"
                    ))
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)

        walk(data)

        if findings:
            return findings, [RuntimeResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]
    except Exception:
        pass

    # text fallback
    for line in raw.splitlines():
        l = line.strip()
        if any(x in l.lower() for x in ["exposed", "vulnerability", "dashboard", "etcd", "api server", "readonly"]):
            sev = "medium"
            if "etcd" in l.lower() or "dashboard" in l.lower():
                sev = "high"
            add_finding(findings, resource_counts, RuntimeFinding(
                category="kubernetes",
                title="kube-hunter finding",
                severity=sev,
                status="warning",
                resource_type="k8s_exposure",
                evidence=l[:2000],
                recommendation="Restrict externally exposed cluster services"
            ))

    return findings, [RuntimeResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]


def parse_kubeaudit_output(stdout: str, stderr: str) -> tuple[list[RuntimeFinding], list[RuntimeResourceSummary]]:
    findings = []
    resource_counts: dict[str, int] = {}
    raw = stdout or stderr
    if not raw.strip():
        return findings, []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)

            severity = "medium"
            if data.get("AuditResultName") in {"allow-privilege-escalation-false", "run-as-non-root", "seccomp", "capabilities", "privileged"}:
                severity = "high"

            add_finding(findings, resource_counts, RuntimeFinding(
                category="kubernetes",
                title=data.get("AuditResultName", "kubeaudit finding"),
                severity=severity,
                status="warning",
                resource_type=data.get("ResourceKind", "k8s_resource"),
                resource_name=data.get("ResourceName"),
                namespace=data.get("Namespace"),
                evidence=json.dumps(data)[:2000],
                recommendation="Harden pod/container security context and admission policy",
                extra={
                    "container": data.get("Container"),
                    "msg": data.get("msg"),
                }
            ))
        except json.JSONDecodeError:
            # text fallback
            if any(x in line.lower() for x in ["privileged", "root", "seccomp", "capabilities", "hostnetwork", "hostpid", "hostipc"]):
                add_finding(findings, resource_counts, RuntimeFinding(
                    category="kubernetes",
                    title="kubeaudit text finding",
                    severity="high",
                    status="warning",
                    resource_type="k8s_resource",
                    evidence=line[:2000],
                    recommendation="Review pod security settings"
                ))

    return findings, [RuntimeResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]


# ══════════════════════════════════════════════════════════════
# 4. CUSTOM CHECKS
# ══════════════════════════════════════════════════════════════

def check_docker_socket() -> list[RuntimeFinding]:
    findings = []
    docker_sock = "/var/run/docker.sock"

    if os.path.exists(docker_sock):
        try:
            st = os.stat(docker_sock)
            mode = oct(st.st_mode & 0o777)
            findings.append(RuntimeFinding(
                category="docker",
                title="Docker socket present",
                severity="high",
                status="warning",
                resource_type="docker_socket",
                resource_name=docker_sock,
                evidence=f"Socket exists with mode {mode}",
                recommendation="Restrict access to docker.sock; exposure can lead to host compromise",
                extra={"mode": mode, "uid": st.st_uid, "gid": st.st_gid}
            ))

            if (st.st_mode & 0o002) or (st.st_mode & 0o020):
                findings.append(RuntimeFinding(
                    category="docker",
                    title="Docker socket permissions may be overly permissive",
                    severity="critical",
                    status="fail",
                    resource_type="docker_socket",
                    resource_name=docker_sock,
                    evidence=f"Mode {mode}",
                    recommendation="Limit docker.sock access to trusted administrators only"
                ))
        except Exception as e:
            findings.append(RuntimeFinding(
                category="docker",
                title="Could not stat Docker socket",
                severity="medium",
                status="warning",
                resource_type="docker_socket",
                resource_name=docker_sock,
                evidence=str(e)[:1000]
            ))
    else:
        findings.append(RuntimeFinding(
            category="docker",
            title="Docker socket not present",
            severity="info",
            status="pass",
            resource_type="docker_socket",
            resource_name=docker_sock,
        ))

    return findings


def check_docker_containers() -> list[RuntimeFinding]:
    findings = []

    if not command_exists("docker"):
        findings.append(RuntimeFinding(
            category="docker",
            title="Docker CLI not installed",
            severity="info",
            status="info",
            resource_type="docker_host",
            resource_name="local",
        ))
        return findings

    stdout, stderr, rc = safe_execute(
        ["docker", "ps", "--format", "{{json .}}"],
        timeout=30
    )
    if rc != 0:
        findings.append(RuntimeFinding(
            category="docker",
            title="Could not enumerate running Docker containers",
            severity="medium",
            status="warning",
            resource_type="docker_host",
            evidence=stderr[:1000]
        ))
        return findings

    containers = []
    for line in stdout.splitlines():
        try:
            containers.append(json.loads(line))
        except Exception:
            continue

    for c in containers:
        cid = c.get("ID")
        name = c.get("Names")

        inspect_out, inspect_err, inspect_rc = safe_execute(
            ["docker", "inspect", cid],
            timeout=30
        )
        if inspect_rc != 0:
            continue

        try:
            data = json.loads(inspect_out)[0]
        except Exception:
            continue

        host_cfg = data.get("HostConfig", {})
        cfg = data.get("Config", {})
        mounts = data.get("Mounts", [])

        if host_cfg.get("Privileged") is True:
            findings.append(RuntimeFinding(
                category="docker",
                title="Privileged container detected",
                severity="critical",
                status="fail",
                resource_type="container",
                resource_name=name,
                evidence=f"Container {name} ({cid}) runs with Privileged=true",
                recommendation="Avoid privileged containers; use least privilege capabilities only"
            ))

        if host_cfg.get("NetworkMode") == "host":
            findings.append(RuntimeFinding(
                category="docker",
                title="Container uses host network mode",
                severity="high",
                status="warning",
                resource_type="container",
                resource_name=name,
                evidence=f"Container {name} uses host networking",
                recommendation="Avoid host networking unless operationally necessary"
            ))

        if host_cfg.get("PidMode") == "host":
            findings.append(RuntimeFinding(
                category="docker",
                title="Container shares host PID namespace",
                severity="high",
                status="warning",
                resource_type="container",
                resource_name=name,
                evidence=f"Container {name} uses host PID namespace",
                recommendation="Avoid host PID namespace for untrusted workloads"
            ))

        if host_cfg.get("IpcMode") == "host":
            findings.append(RuntimeFinding(
                category="docker",
                title="Container shares host IPC namespace",
                severity="medium",
                status="warning",
                resource_type="container",
                resource_name=name,
                evidence=f"Container {name} uses host IPC namespace",
                recommendation="Avoid host IPC unless required"
            ))

        if cfg.get("User") in {"", "0", "root", None}:
            findings.append(RuntimeFinding(
                category="docker",
                title="Container may be running as root",
                severity="high",
                status="warning",
                resource_type="container",
                resource_name=name,
                evidence=f"Config.User={cfg.get('User')}",
                recommendation="Run containers as a non-root user where possible"
            ))

        for m in mounts:
            src = m.get("Source", "")
            dst = m.get("Destination", "")
            rw = m.get("RW")
            if src == "/" or dst == "/host" or "/var/run/docker.sock" in src or "/var/run/docker.sock" in dst:
                findings.append(RuntimeFinding(
                    category="docker",
                    title="Sensitive host mount detected",
                    severity="critical" if "docker.sock" in src or "docker.sock" in dst else "high",
                    status="fail",
                    resource_type="container",
                    resource_name=name,
                    evidence=json.dumps(m)[:1500],
                    recommendation="Remove sensitive host mounts such as / or docker.sock"
                ))
            elif rw and src.startswith("/etc"):
                findings.append(RuntimeFinding(
                    category="docker",
                    title="Writable /etc host mount detected",
                    severity="high",
                    status="warning",
                    resource_type="container",
                    resource_name=name,
                    evidence=json.dumps(m)[:1500],
                    recommendation="Avoid writable mounts of sensitive host directories"
                ))

    if not findings and containers:
        findings.append(RuntimeFinding(
            category="docker",
            title="No obvious risky Docker runtime settings detected",
            severity="info",
            status="pass",
            resource_type="docker_host",
            resource_name="local",
            evidence=f"Checked {len(containers)} containers"
        ))

    return findings


def check_kubernetes_custom() -> list[RuntimeFinding]:
    findings = []

    if not command_exists("kubectl"):
        findings.append(RuntimeFinding(
            category="kubernetes",
            title="kubectl not installed",
            severity="info",
            status="info",
            resource_type="k8s_cluster",
            resource_name="local",
        ))
        return findings

    # Pods
    pods_out, pods_err, pods_rc = safe_execute(["kubectl", "get", "pods", "-A", "-o", "json"], timeout=60)
    if pods_rc == 0:
        try:
            data = json.loads(pods_out)
            for item in data.get("items", []):
                ns = item.get("metadata", {}).get("namespace")
                pod_name = item.get("metadata", {}).get("name")
                spec = item.get("spec", {})

                if spec.get("hostNetwork") is True:
                    findings.append(RuntimeFinding(
                        category="kubernetes",
                        title="Pod uses hostNetwork",
                        severity="high",
                        status="warning",
                        resource_type="pod",
                        resource_name=pod_name,
                        namespace=ns,
                        recommendation="Avoid hostNetwork unless required",
                    ))
                if spec.get("hostPID") is True:
                    findings.append(RuntimeFinding(
                        category="kubernetes",
                        title="Pod uses hostPID",
                        severity="high",
                        status="warning",
                        resource_type="pod",
                        resource_name=pod_name,
                        namespace=ns,
                        recommendation="Avoid hostPID unless required",
                    ))
                if spec.get("hostIPC") is True:
                    findings.append(RuntimeFinding(
                        category="kubernetes",
                        title="Pod uses hostIPC",
                        severity="medium",
                        status="warning",
                        resource_type="pod",
                        resource_name=pod_name,
                        namespace=ns,
                        recommendation="Avoid hostIPC unless required",
                    ))

                for c in spec.get("containers", []):
                    sec = c.get("securityContext", {})
                    if sec.get("privileged") is True:
                        findings.append(RuntimeFinding(
                            category="kubernetes",
                            title="Privileged container detected",
                            severity="critical",
                            status="fail",
                            resource_type="container",
                            resource_name=c.get("name"),
                            namespace=ns,
                            evidence=f"Pod={pod_name}",
                            recommendation="Do not run privileged containers unless absolutely necessary"
                        ))
                    if sec.get("allowPrivilegeEscalation") is not False:
                        findings.append(RuntimeFinding(
                            category="kubernetes",
                            title="allowPrivilegeEscalation not disabled",
                            severity="high",
                            status="warning",
                            resource_type="container",
                            resource_name=c.get("name"),
                            namespace=ns,
                            evidence=f"Pod={pod_name}",
                            recommendation="Set allowPrivilegeEscalation: false"
                        ))
                    run_as_non_root = sec.get("runAsNonRoot")
                    if run_as_non_root is not True:
                        findings.append(RuntimeFinding(
                            category="kubernetes",
                            title="Container not explicitly configured to run as non-root",
                            severity="medium",
                            status="warning",
                            resource_type="container",
                            resource_name=c.get("name"),
                            namespace=ns,
                            evidence=f"Pod={pod_name}",
                            recommendation="Set runAsNonRoot: true and use a non-root image user"
                        ))
        except Exception:
            pass

    # RBAC
    rbac_out, _, rbac_rc = safe_execute(["kubectl", "get", "clusterrolebindings", "-o", "json"], timeout=60)
    if rbac_rc == 0:
        try:
            data = json.loads(rbac_out)
            for item in data.get("items", []):
                name = item.get("metadata", {}).get("name")
                role_ref = item.get("roleRef", {})
                subjects = item.get("subjects", []) or []
                if role_ref.get("name") == "cluster-admin":
                    findings.append(RuntimeFinding(
                        category="kubernetes",
                        title="cluster-admin ClusterRoleBinding detected",
                        severity="high",
                        status="warning",
                        resource_type="clusterrolebinding",
                        resource_name=name,
                        evidence=json.dumps(item)[:2000],
                        recommendation="Review cluster-admin bindings and reduce excessive RBAC privileges"
                    ))
                for subj in subjects:
                    if subj.get("kind") == "Group" and subj.get("name") in {"system:authenticated", "system:unauthenticated"}:
                        findings.append(RuntimeFinding(
                            category="kubernetes",
                            title="Broad RBAC subject detected",
                            severity="critical",
                            status="fail",
                            resource_type="clusterrolebinding",
                            resource_name=name,
                            evidence=json.dumps(subj)[:1000],
                            recommendation="Do not bind powerful roles to broad authenticated/unauthenticated groups"
                        ))
        except Exception:
            pass

    # Pod Security admission / PSP existence
    psp_out, psp_err, psp_rc = safe_execute(["kubectl", "get", "psp", "-o", "json"], timeout=30)
    if psp_rc == 0:
        findings.append(RuntimeFinding(
            category="kubernetes",
            title="PodSecurityPolicies detected",
            severity="info",
            status="info",
            resource_type="psp",
            resource_name="cluster",
            recommendation="If deprecated PSPs are still in use, plan migration to Pod Security Admission or policy engine"
        ))
    else:
        ns_out, _, ns_rc = safe_execute(["kubectl", "get", "ns", "--show-labels"], timeout=30)
        if ns_rc == 0:
            findings.append(RuntimeFinding(
                category="kubernetes",
                title="PSP not detected; verify Pod Security Admission labels/policies",
                severity="medium",
                status="warning",
                resource_type="k8s_cluster",
                resource_name="cluster",
                evidence=ns_out[:1500],
                recommendation="Use Pod Security Admission or an equivalent policy controller"
            ))

    # etcd port local exposure
    for host in ["127.0.0.1", "0.0.0.0"]:
        try:
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex((host, 2379)) == 0:
                findings.append(RuntimeFinding(
                    category="kubernetes",
                    title="etcd port appears reachable",
                    severity="critical",
                    status="fail",
                    resource_type="etcd",
                    resource_name=f"{host}:2379",
                    recommendation="Restrict etcd network exposure and require TLS/authentication"
                ))
            s.close()
        except Exception:
            pass

    if not findings:
        findings.append(RuntimeFinding(
            category="kubernetes",
            title="No obvious custom Kubernetes runtime issues detected",
            severity="info",
            status="pass",
            resource_type="k8s_cluster",
            resource_name="cluster"
        ))

    return findings


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def container_runtime_audit(tool: str, target: str = "local", args: list[str] = []) -> dict:
    """
    🐳 Agent Tool: Container Runtime & Kubernetes Audit

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  DOCKER SOCKET        exposed docker.sock / weak perms      │
      │  PRIVILEGED CTRS      privileged, hostPID, hostNetwork      │
      │  SENSITIVE MOUNTS     /, docker.sock, writable host paths   │
      │  K8S RBAC             cluster-admin, broad group bindings    │
      │  POD SECURITY         privileged pods, root, priv-esc       │
      │  PSP / PSA            policy presence / missing hardening    │
      │  ETCD EXPOSURE        port 2379 reachable                    │
      │  BENCHMARK TOOLS      docker-bench / kube-bench / etc.      │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:   "docker-bench-security" | "kube-bench" | "kube-hunter" | "kubeaudit" | "custom"
        target: usually "local" or cluster context hint
        args:   raw tool args

    Returns:
        Structured JSON findings about container runtime and Kubernetes posture
    """

    start = time.time()

    try:
        req = ContainerRuntimeAuditRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return ContainerRuntimeAuditResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation: {e}",
        ).model_dump()

    findings: list[RuntimeFinding] = []
    resource_counts: dict[str, int] = {}
    command_str = ""

    # ══════════════════════════════
    # EXECUTE TOOL / CUSTOM
    # ══════════════════════════════
    if req.tool == "docker-bench-security":
        cmd = ["docker-bench-security"] + list(req.args)
        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout)
        findings, resource_summary = parse_docker_bench_output(stdout, stderr)

    elif req.tool == "kube-bench":
        cmd = ["kube-bench"] + list(req.args)
        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout)
        findings, resource_summary = parse_kube_bench_output(stdout, stderr)

    elif req.tool == "kube-hunter":
        cmd = ["kube-hunter"] + list(req.args)
        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout)
        findings, resource_summary = parse_kube_hunter_output(stdout, stderr)

    elif req.tool == "kubeaudit":
        cmd = ["kubeaudit"] + list(req.args)
        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout)
        findings, resource_summary = parse_kubeaudit_output(stdout, stderr)

    elif req.tool == "custom":
        command_str = "custom runtime checks"
        stdout, stderr, rc = "", "", 0

        for f in check_docker_socket():
            add_finding(findings, resource_counts, f)
        for f in check_docker_containers():
            add_finding(findings, resource_counts, f)
        for f in check_kubernetes_custom():
            add_finding(findings, resource_counts, f)

        resource_summary = [RuntimeResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]

    else:
        return ContainerRuntimeAuditResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Unknown tool: {tool}",
        ).model_dump()

    severity_summary: dict[str, int] = {}
    for f in findings:
        severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1

    return ContainerRuntimeAuditResult(
        success=(len(findings) > 0 or rc == 0),
        tool=req.tool,
        target=req.target,
        command=command_str,
        total_findings=len(findings),
        severity_summary=severity_summary,
        resource_summary=resource_summary,
        findings=findings,
        raw_output=(stdout or stderr)[:12000] if req.tool != "custom" else None,
        error=stderr[:4000] if req.tool != "custom" and rc != 0 and not findings else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

CONTAINER_RUNTIME_AUDIT_TOOL_DEFINITION = {
    "name": "container_runtime_audit",
    "description": (
        "Audit Docker/container runtime and Kubernetes security posture. "
        "Checks for exposed docker.sock, privileged containers, sensitive host mounts, "
        "Kubernetes RBAC misconfigurations, weak pod security settings, missing policy controls, "
        "and etcd exposure. Supports docker-bench-security, kube-bench, kube-hunter, kubeaudit, or custom checks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["docker-bench-security", "kube-bench", "kube-hunter", "kubeaudit", "custom"],
                "description": (
                    "docker-bench-security = Docker host benchmark | "
                    "kube-bench = CIS Kubernetes benchmark | "
                    "kube-hunter = cluster exposure hunting | "
                    "kubeaudit = pod/RBAC security review | "
                    "custom = built-in Docker + Kubernetes checks"
                ),
            },
            "target": {
                "type": "string",
                "description": "Usually 'local' or a cluster/context hint",
                "default": "local"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "kube-bench: ['--json']\n"
                    "kube-hunter: ['--remote', '10.10.10.10']\n"
                    "kubeaudit: ['all', '-f', 'manifest.yaml']\n"
                    "docker-bench-security: []"
                )
            }
        },
        "required": ["tool"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Custom local runtime audit
    # ─────────────────────────────
    r = container_runtime_audit(
        tool="custom",
        target="local",
        args=[]
    )
    print("=== CUSTOM RUNTIME AUDIT ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Docker benchmark
    # ─────────────────────────────
    r = container_runtime_audit(
        tool="docker-bench-security",
        target="local",
        args=[]
    )
    print("=== DOCKER BENCH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Kubernetes CIS benchmark
    # ─────────────────────────────
    r = container_runtime_audit(
        tool="kube-bench",
        target="local",
        args=["--json"]
    )
    print("=== KUBE BENCH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Kubernetes exposure hunting
    # ─────────────────────────────
    r = container_runtime_audit(
        tool="kube-hunter",
        target="local",
        args=[]
    )
    print("=== KUBE HUNTER ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Kubernetes manifest / cluster audit
    # ─────────────────────────────
    r = container_runtime_audit(
        tool="kubeaudit",
        target="local",
        args=["all"]
    )
    print("=== KUBEAUDIT ===")
    print(json.dumps(r, indent=2))