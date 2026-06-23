#!/usr/bin/env bash
set -Eeuo pipefail

TOOLS_ROOT="/opt/pentaforge-tools"
BIN_DIR="/usr/local/bin"
STRICT_MODE="${PENTAFORGE_SANDBOX_STRICT_TOOL_INSTALL:-0}"

mkdir -p "${TOOLS_ROOT}" "${TOOLS_ROOT}/bin" /root/.config/amass
: > /root/.config/amass/config.ini

export DEBIAN_FRONTEND=noninteractive
export PIP_BREAK_SYSTEM_PACKAGES=1
export TOOLS_ROOT BIN_DIR DEBIAN_FRONTEND PIP_BREAK_SYSTEM_PACKAGES

FAILED_TOOLS=()
INSTALLED_TOOLS=()

mkdir -p /etc/apt/keyrings /usr/share/keyrings

log() {
  printf '[sandbox-tools] %s\n' "$*"
}

record_success() {
  INSTALLED_TOOLS+=("$1")
  log "installed: $1"
}

record_failure() {
  FAILED_TOOLS+=("$1")
  log "failed: $1"
}

run_best_effort() {
  local name="$1"
  shift
  log "installing ${name}..."
  if "$@"; then
    record_success "$name"
  else
    record_failure "$name"
  fi
}

install_go_tool() {
  local name="$1"
  local module="$2"
  GOBIN="${BIN_DIR}" go install "${module}"
}

clone_repo() {
  local repo="$1"
  local dest="$2"
  rm -rf "${dest}"
  git clone --depth 1 "${repo}" "${dest}"
}

link_alias() {
  local source="$1"
  local alias_name="$2"
  ln -sf "${source}" "${BIN_DIR}/${alias_name}"
}

install_pip_packages() {
  local failed=0
  for pkg in "$@"; do
    if [[ "${pkg}" == "repo-supervisor" ]]; then continue; fi
    log "installing pip package ${pkg}..."
    if python3 -m pip install --prefer-binary "${pkg}"; then
      log "successfully installed pip package: ${pkg}"
    else
      log "warning: pip package ${pkg} failed standard install, trying with only-binary..."
      if python3 -m pip install --prefer-binary --only-binary=:all: "${pkg}"; then
        log "successfully installed pip package via only-binary: ${pkg}"
      else
        log "error: failed to install pip package ${pkg}"
        failed=1
      fi
    fi
  done
  return ${failed}
}


write_python_wrapper() {
  local wrapper_name="$1"
  local script_path="$2"
  cat > "${BIN_DIR}/${wrapper_name}" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec python3 "${script_path}" "\$@"
EOF
  chmod +x "${BIN_DIR}/${wrapper_name}"
}

export -f log install_go_tool clone_repo link_alias install_pip_packages write_python_wrapper

log "installing extended apt packages..."
run_best_effort "apt-masscan" bash -c '
  apt-get update && apt-get install -y --no-install-recommends masscan
'
run_best_effort "apt-nikto" bash -c '
  clone_repo "https://github.com/sullo/nikto.git" "${TOOLS_ROOT}/nikto"
  ln -sf "${TOOLS_ROOT}/nikto/program/nikto.pl" "${BIN_DIR}/nikto"
'
run_best_effort "apt-whatweb" bash -c '
  apt-get update && apt-get install -y --no-install-recommends whatweb
'
run_best_effort "apt-network-stack" bash -c '
  echo "wireshark-common wireshark-common/install-sysusers boolean true" | debconf-set-selections
  apt-get update && apt-get install -y --no-install-recommends arp-scan dnsrecon fping ike-scan ldap-utils mtr nbtscan netdiscover nfs-common onesixtyone proxychains4 rpcbind smbclient snmp tcpdump tshark
'
run_best_effort "besttrace-install" bash -c '
  curl -L "https://github.com/sjlleo/nexttrace/releases/latest/download/nexttrace_linux_amd64" -o /usr/local/bin/besttrace
  chmod +x /usr/local/bin/besttrace
'
run_best_effort "rustscan-install" bash -c '
  ASSET_URL=$(curl -fsSL https://api.github.com/repos/RustScan/RustScan/releases/latest | grep -o "https://[^\"]*rustscan[^\"]*_amd64\\.deb" | head -n 1 || true)
  if [[ -z "${ASSET_URL}" ]]; then
    ASSET_URL="https://github.com/RustScan/RustScan/releases/download/v2.3.0/rustscan_2.3.0_amd64.deb"
  fi
  curl -fL "${ASSET_URL}" -o rustscan.deb
  dpkg -i rustscan.deb && rm rustscan.deb
'
run_best_effort "apt-mobile-static-stack" bash -c '
  apt-get update && apt-get install -y --no-install-recommends apktool binwalk default-jdk-headless
'

run_best_effort "jadx-install" bash -c '
  VERSION=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep tag_name | cut -d "\"" -f 4 || echo "v1.4.7")
  if [[ -z "${VERSION}" ]]; then VERSION="v1.4.7"; fi
  curl -L "https://github.com/skylot/jadx/releases/download/${VERSION}/jadx-${VERSION:1}.zip" -o jadx.zip
  unzip -oq jadx.zip -d /opt/pentaforge-tools/jadx && rm jadx.zip
  ln -sf /opt/pentaforge-tools/jadx/bin/jadx /usr/local/bin/jadx
  ln -sf /opt/pentaforge-tools/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
'

run_best_effort "apt-container-cloud-stack" bash -c '
  apt-get update && apt-get install -y --no-install-recommends awscli kubernetes-client skopeo yq
'
run_best_effort "apt-exploitation" bash -c '
  apt-get update && apt-get install -y --no-install-recommends hydra john openssh-client ftp
'

log "installing npm globals..."
run_best_effort "npm-js-beautify" npm install -g js-beautify
run_best_effort "npm-wappalyzer-cli" npm install -g wappalyzer-cli
run_best_effort "npm-retire" npm install -g retire
run_best_effort "npm-newman" npm install -g newman

log "installing pip toolchains..."
run_best_effort "pip-recon-core" install_pip_packages \
  wafw00f \
  mitmproxy \
  theHarvester \
  recon-ng \
  bandit \
  checkov \
  apkid \
  prowler \
  safety \
  semgrep \
  shodan \
  censys \
  sshuttle

run_best_effort "ligolo-ng-agent-install" bash -c '
  VERSION=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep tag_name | cut -d "\"" -f 4 || echo "v0.7.2")
  if [[ -z "${VERSION}" ]]; then VERSION="v0.7.2"; fi
  curl -L "https://github.com/nicocha30/ligolo-ng/releases/download/${VERSION}/ligolo-ng-agent_linux_amd64.tar.gz" -o ligolo-ng-agent.tar.gz
  tar -xzf ligolo-ng-agent.tar.gz && mv agent /usr/local/bin/ligolo-ng-agent && rm ligolo-ng-agent.tar.gz
'

log "installing official cloud sdks..."
run_best_effort "apt-azure-cli" bash -c '
  AZURE_CODENAME=$(lsb_release -cs)
  if [[ "${AZURE_CODENAME}" == "trixie" ]]; then
    AZURE_CODENAME="bookworm"
  fi
  curl -sLS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ ${AZURE_CODENAME} main" > /etc/apt/sources.list.d/azure-cli.list
  apt-get update && apt-get install -y azure-cli
'
run_best_effort "apt-gcloud-sdk" bash -c '
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
  apt-get update && apt-get install -y --no-install-recommends google-cloud-sdk
'
run_best_effort "apt-docker-cli" bash -c '
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update && apt-get install -y --no-install-recommends docker-ce-cli
'
run_best_effort "apt-nomad" bash -c '
  curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
  apt-get update && apt-get install -y --no-install-recommends nomad
'
run_best_effort "kube-bench-install" bash -c '
  VERSION=$(curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | grep tag_name | cut -d "\"" -f 4 || echo "v0.8.0")
  if [[ -z "${VERSION}" ]]; then VERSION="v0.8.0"; fi
  curl -L "https://github.com/aquasecurity/kube-bench/releases/download/${VERSION}/kube-bench_${VERSION:1}_linux_amd64.tar.gz" -o kube-bench.tar.gz
  tar -xzf kube-bench.tar.gz && mv kube-bench /usr/local/bin/ && rm kube-bench.tar.gz
'
run_best_effort "calicoctl-install" bash -c '
  curl -L https://github.com/projectcalico/calico/releases/latest/download/calicoctl-linux-amd64 -o /usr/local/bin/calicoctl
  chmod +x /usr/local/bin/calicoctl
'
run_best_effort "apt-gh-cli" bash -c '
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list
  apt-get update && apt-get install -y --no-install-recommends gh
'
run_best_effort "apt-glab-cli" bash -c '
  curl -sSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-explorer/script.deb.sh | bash
  apt-get install -y glab
'
run_best_effort "codeql-install" bash -c '
  VERSION=$(curl -s https://api.github.com/repos/github/codeql-cli-binaries/releases/latest | grep tag_name | cut -d "\"" -f 4 || echo "v2.17.5")
  if [[ -z "${VERSION}" ]]; then VERSION="v2.17.5"; fi
  curl -L "https://github.com/github/codeql-cli-binaries/releases/download/${VERSION}/codeql-linux64.zip" -o codeql.zip
  rm -rf "${TOOLS_ROOT}/codeql"
  unzip -oq codeql.zip -d "${TOOLS_ROOT}" && rm codeql.zip
  link_alias "${TOOLS_ROOT}/codeql/codeql" "codeql"
'

run_best_effort "pip-s3scanner" install_pip_packages s3scanner
run_best_effort "pip-web-api-tools" install_pip_packages \
  arjun \
  zap-cli \
  param-miner \
  pyjwt \
  graphw00f \
  git-dumper \
  inql \
  sslyze \
  droopescan \
  pyntcli

run_best_effort "pip-network-repo-tools" install_pip_packages \
  detect-secrets \
  knockpy \
  ldapdomaindump \
  bloodhound \
  ssh-audit

run_best_effort "pip-ad-tools" install_pip_packages \
  impacket \
  smbmap \
  crackmapexec \
  netexec \
  enum4linux-ng

run_best_effort "pip-cloud-container-tools" install_pip_packages \
  kube-hunter \
  scoutsuite

run_best_effort "pip-cloud-aws-tools" install_pip_packages pacu


log "installing go binaries..."
run_best_effort "subfinder" install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
run_best_effort "httpx" install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
run_best_effort "katana" install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
run_best_effort "gospider" install_go_tool gospider github.com/jaeles-project/gospider@latest
run_best_effort "gau" install_go_tool gau github.com/lc/gau/v2/cmd/gau@latest
run_best_effort "dnsx" install_go_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest
run_best_effort "nuclei" install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
run_best_effort "amass" install_go_tool amass github.com/owasp-amass/amass/v4/.../amass@latest
run_best_effort "tlsx" install_go_tool tlsx github.com/projectdiscovery/tlsx/cmd/tlsx@latest
run_best_effort "subjs" install_go_tool subjs github.com/lc/subjs@latest
run_best_effort "ffuf" install_go_tool ffuf github.com/ffuf/ffuf/v2@latest
run_best_effort "gobuster" install_go_tool gobuster github.com/OJ/gobuster/v3@latest
run_best_effort "naabu" install_go_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
run_best_effort "alterx" install_go_tool alterx github.com/projectdiscovery/alterx/cmd/alterx@latest
run_best_effort "subjack" install_go_tool subjack github.com/haccer/subjack@latest
run_best_effort "dalfox" install_go_tool dalfox github.com/hahwul/dalfox/v2@latest
run_best_effort "gowitness" install_go_tool gowitness github.com/sensepost/gowitness@latest
run_best_effort "k9s" install_go_tool k9s github.com/derailed/k9s@latest
run_best_effort "interactsh-client" install_go_tool interactsh-client github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
run_best_effort "kiterunner" bash -c '
  clone_repo "https://github.com/assetnote/kiterunner.git" "${TOOLS_ROOT}/kiterunner"
  cd "${TOOLS_ROOT}/kiterunner"
  make build
  ln -sf "${TOOLS_ROOT}/kiterunner/dist/kr" "${BIN_DIR}/kiterunner"
  ln -sf "${TOOLS_ROOT}/kiterunner/dist/kr" "${BIN_DIR}/kr"
'
run_best_effort "grpcurl" install_go_tool grpcurl github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
run_best_effort "zgrab2" bash -c '
  clone_repo "https://github.com/zmap/zgrab2.git" "${TOOLS_ROOT}/zgrab2"
  cd "${TOOLS_ROOT}/zgrab2"
  make
  ln -sf "${TOOLS_ROOT}/zgrab2/zgrab2" "${BIN_DIR}/zgrab2"
'
run_best_effort "chisel" install_go_tool chisel github.com/jpillora/chisel@latest
run_best_effort "ctop" bash -c '
  VERSION=$(curl -s https://api.github.com/repos/bcicen/ctop/releases/latest | grep tag_name | cut -d "\"" -f 4 || echo "v0.7.7")
  if [[ -z "${VERSION}" ]]; then VERSION="v0.7.7"; fi
  curl -L "https://github.com/bcicen/ctop/releases/download/${VERSION}/ctop-${VERSION:1}-linux-amd64" -o /usr/local/bin/ctop
  chmod +x /usr/local/bin/ctop
'
run_best_effort "crane" install_go_tool crane github.com/google/go-containerregistry/cmd/crane@latest
run_best_effort "stern" install_go_tool stern github.com/stern/stern@latest
run_best_effort "unfurl" install_go_tool unfurl github.com/tomnomnom/unfurl@latest
run_best_effort "syft" install_go_tool syft github.com/anchore/syft/cmd/syft@latest
run_best_effort "grype" bash -c 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin'
run_best_effort "dive" install_go_tool dive github.com/wagoodman/dive@latest
run_best_effort "gitleaks" bash -c '
  VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d "\"" -f 4 || echo "v8.18.2")
  if [[ -z "${VERSION}" ]]; then VERSION="v8.18.2"; fi
  curl -L "https://github.com/gitleaks/gitleaks/releases/download/${VERSION}/gitleaks_${VERSION:1}_linux_x64.tar.gz" -o gitleaks.tar.gz
  tar -xzf gitleaks.tar.gz -C /usr/local/bin gitleaks && rm gitleaks.tar.gz
'
run_best_effort "trufflehog" bash -c '
  TRUFFLEHOG_VERSION="3.95.6"
  curl -L "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" -o trufflehog.tar.gz
  tar -xzf trufflehog.tar.gz -C /usr/local/bin trufflehog && rm trufflehog.tar.gz
'
run_best_effort "osv-scanner" install_go_tool osv-scanner github.com/google/osv-scanner/cmd/osv-scanner@latest
run_best_effort "kerbrute" install_go_tool kerbrute github.com/ropnop/kerbrute@latest
run_best_effort "actionlint" install_go_tool actionlint github.com/rhysd/actionlint/cmd/actionlint@latest
run_best_effort "diggit" bash -c '
  cat > /usr/local/bin/diggit << "EOF"
#!/usr/bin/env python3
import sys
import argparse
import subprocess
import tempfile
import os

parser = argparse.ArgumentParser(description="Git repository harvester wrapper")
parser.add_argument("-u", "--url", required=True, help="Target URL containing exposed .git directory")
parser.add_argument("-o", "--output", required=True, help="Output destination (if - then stdout)")

args = parser.parse_args()

if args.output == "-":
    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = ["git-dumper", args.url, tmpdir]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for root, dirs, files in os.walk(tmpdir):
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), tmpdir)
                print(f"[+] downloaded: {rel_path}")
else:
    cmd = ["git-dumper", args.url, args.output]
    subprocess.run(cmd)
EOF
  chmod +x /usr/local/bin/diggit
'

run_best_effort "cloudbrute" bash -c '
  clone_repo "https://github.com/0xsha/CloudBrute" "${TOOLS_ROOT}/CloudBrute"
  cd "${TOOLS_ROOT}/CloudBrute"
  go build -o "${BIN_DIR}/cloudbrute" main.go
'

run_best_effort "paramspider-repo" bash -c '
  clone_repo "https://github.com/devanshbatham/paramspider" "${TOOLS_ROOT}/paramspider"
  cd "${TOOLS_ROOT}/paramspider"
  python3 -m pip install --prefer-binary .
  link_alias "$(which paramspider)" "paramspider"
'

log "installing system security tools..."
run_best_effort "apt-security-core" bash -c '
  apt-get update && apt-get install -y --no-install-recommends nmap amap hashcat netcat-traditional protobuf-compiler
  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
  chmod +x msfinstall
  ./msfinstall --non-interactive || true
  rm -f msfinstall
'

log "installing binary utilities..."
run_best_effort "pspy-install" bash -c 'curl -sfL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /usr/local/bin/pspy && chmod +x /usr/local/bin/pspy'

log "installing vendor repos..."
run_best_effort "linkfinder-repo" clone_repo https://github.com/GerbenJavado/LinkFinder.git "${TOOLS_ROOT}/LinkFinder"
run_best_effort "secretfinder-repo" clone_repo https://github.com/m4ll0k/SecretFinder.git "${TOOLS_ROOT}/SecretFinder"
run_best_effort "cloud-enum-repo" clone_repo https://github.com/initstring/cloud_enum.git "${TOOLS_ROOT}/cloud_enum"
run_best_effort "corscanner-repo" clone_repo https://github.com/chenjj/CORScanner.git "${TOOLS_ROOT}/CORScanner"
run_best_effort "sqlmap-repo" clone_repo https://github.com/sqlmapproject/sqlmap.git "${TOOLS_ROOT}/sqlmap"
run_best_effort "nosqlmap-repo" clone_repo https://github.com/codingo/NoSQLMap.git "${TOOLS_ROOT}/NoSQLMap"
run_best_effort "jwt-tool-repo" clone_repo https://github.com/ticarpi/jwt_tool.git "${TOOLS_ROOT}/jwt_tool"
run_best_effort "xsstrike-repo" clone_repo https://github.com/s0md3v/XSStrike.git "${TOOLS_ROOT}/XSStrike"
run_best_effort "commix-repo" clone_repo https://github.com/commixproject/commix.git "${TOOLS_ROOT}/commix"
run_best_effort "massdns-install" bash -c '
  clone_repo "https://github.com/blechschmidt/massdns.git" "${TOOLS_ROOT}/massdns"
  cd "${TOOLS_ROOT}/massdns"
  make -j$(nproc)
  link_alias "${TOOLS_ROOT}/massdns/bin/massdns" "massdns"
'
run_best_effort "cmseek-repo" clone_repo https://github.com/Tuhinshubhra/CMSeeK.git "${TOOLS_ROOT}/cmseek"
run_best_effort "cmseek-deps" python3 -m pip install --prefer-binary -r "${TOOLS_ROOT}/cmseek/requirements.txt"
write_python_wrapper "cmseek" "${TOOLS_ROOT}/cmseek/cmseek.py"

run_best_effort "feroxbuster-install" bash -c '
  curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash -s /usr/local/bin
'
run_best_effort "tplmap-repo" clone_repo https://github.com/epinna/tplmap.git "${TOOLS_ROOT}/tplmap"
run_best_effort "ssrfmap-repo" clone_repo https://github.com/swisskyrepo/SSRFmap.git "${TOOLS_ROOT}/SSRFmap"
run_best_effort "graphql-cop-repo" clone_repo https://github.com/dolevf/graphql-cop.git "${TOOLS_ROOT}/graphql-cop"
run_best_effort "apt-extra-net" apt-get install -y --no-install-recommends \
  nfs-common \
  snmp \
  iputils-ping \
  mtr-tiny

run_best_effort "stormspotter-install" python3 -m pip install --prefer-binary stormspotter || log "stormspotter-install failed or was skipped"
run_best_effort "gcpbucketbrute-repo" clone_repo https://github.com/RhinoSecurityLabs/GCPBucketBrute.git "${TOOLS_ROOT}/GCPBucketBrute"

run_best_effort "oauth-scanner-repo" bash -c '
  mkdir -p "${TOOLS_ROOT}/OAuth-Scanner"
  cat > "${TOOLS_ROOT}/OAuth-Scanner/oauth-scanner.py" << "EOF"
#!/usr/bin/env python3
import sys
import argparse
import urllib.request
import json

parser = argparse.ArgumentParser(description="Lightweight OAuth/OpenID Scanner")
parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
parser.add_argument("-c", "--client-id", help="Client ID for testing")
parser.add_argument("--json", type=int, help="JSON output detail level")

args = parser.parse_args()

findings = []
endpoints = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth2/authorize",
    "/oauth2/token"
]

for ep in endpoints:
    url = args.url.rstrip("/") + ep
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                findings.append({
                    "type": "exposed_oauth_endpoint",
                    "endpoint": ep,
                    "details": f"Found active OAuth endpoint at {url}"
                })
    except Exception:
        pass

print(json.dumps({"findings": findings}))
EOF
  chmod +x "${TOOLS_ROOT}/OAuth-Scanner/oauth-scanner.py"
'

run_best_effort "joomscan-repo" clone_repo https://github.com/OWASP/joomscan.git "${TOOLS_ROOT}/joomscan"
run_best_effort "linpeas-repo" clone_repo https://github.com/peass-ng/PEASS-ng.git "${TOOLS_ROOT}/PEASS-ng"
run_best_effort "firmwalker-repo" clone_repo https://github.com/craigz28/firmwalker.git "${TOOLS_ROOT}/firmwalker"

run_best_effort "rdp-sec-check-repo" clone_repo https://github.com/CiscoCXSecurity/rdp-sec-check.git "${TOOLS_ROOT}/rdp-sec-check"

log "installing automation & iac tools..."
run_best_effort "pulumi-install" bash -c 'curl -fsSL https://get.pulumi.com | sh'
run_best_effort "steampipe-install" bash -c 'sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"'
run_best_effort "kubectx-repo" clone_repo https://github.com/ahmetb/kubectx.git "${TOOLS_ROOT}/kubectx"
run_best_effort "testssl-repo" clone_repo https://github.com/drwetter/testssl.sh.git "${TOOLS_ROOT}/testssl.sh"
run_best_effort "exploitdb-repo" clone_repo https://gitlab.com/exploit-database/exploitdb.git "${TOOLS_ROOT}/exploitdb"
run_best_effort "lse-install" bash -c 'curl -sfL https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -o /usr/local/bin/lse && chmod +x /usr/local/bin/lse'
run_best_effort "trivy-install" bash -c 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin'
run_best_effort "wpscan-install" gem install wpscan || log "wpscan-install skipped or failed"

log "installing repo-specific python deps..."
run_best_effort "linkfinder-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/LinkFinder/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/LinkFinder/requirements.txt"'" || true'
run_best_effort "secretfinder-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/SecretFinder/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/SecretFinder/requirements.txt"'" || true'
run_best_effort "cloud-enum-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/cloud_enum/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/cloud_enum/requirements.txt"'" || true'
run_best_effort "corscanner-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/CORScanner/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/CORScanner/requirements.txt"'" || true'
run_best_effort "sqlmap-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/sqlmap/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/sqlmap/requirements.txt"'" || true'
run_best_effort "nosqlmap-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/NoSQLMap/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/NoSQLMap/requirements.txt"'" || true'
run_best_effort "jwt-tool-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/jwt_tool/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/jwt_tool/requirements.txt"'" || true'
run_best_effort "xsstrike-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/XSStrike/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/XSStrike/requirements.txt"'" || true'
run_best_effort "commix-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/commix/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/commix/requirements.txt"'" || true'
run_best_effort "tplmap-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/tplmap/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/tplmap/requirements.txt"'" || true'
run_best_effort "ssrfmap-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/SSRFmap/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/SSRFmap/requirements.txt"'" || true'
run_best_effort "gcpbucketbrute-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/GCPBucketBrute/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/GCPBucketBrute/requirements.txt"'" || true'
run_best_effort "oauth-scanner-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/OAuth-Scanner/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/OAuth-Scanner/requirements.txt"'" || true'
run_best_effort "graphql-cop-deps" bash -c 'test ! -f "'"${TOOLS_ROOT}/graphql-cop/requirements.txt"'" || python3 -m pip install --prefer-binary -r "'"${TOOLS_ROOT}/graphql-cop/requirements.txt"'" || true'

log "writing wrappers..."
if [[ -f "${TOOLS_ROOT}/LinkFinder/linkfinder.py" ]]; then
  write_python_wrapper "linkfinder" "${TOOLS_ROOT}/LinkFinder/linkfinder.py"
fi
if [[ -f "${TOOLS_ROOT}/SecretFinder/SecretFinder.py" ]]; then
  write_python_wrapper "secretfinder" "${TOOLS_ROOT}/SecretFinder/SecretFinder.py"
  # Also make sure it's executable directly just in case
  chmod +x "${TOOLS_ROOT}/SecretFinder/SecretFinder.py"
fi
if [[ -f "${TOOLS_ROOT}/cloud_enum/cloud_enum.py" ]]; then
  write_python_wrapper "cloud_enum" "${TOOLS_ROOT}/cloud_enum/cloud_enum.py"
fi
if [[ -f "${TOOLS_ROOT}/sqlmap/sqlmap.py" ]]; then
  write_python_wrapper "sqlmap" "${TOOLS_ROOT}/sqlmap/sqlmap.py"
fi
if [[ -f "${TOOLS_ROOT}/NoSQLMap/nosqlmap.py" ]]; then
  write_python_wrapper "nosqlmap" "${TOOLS_ROOT}/NoSQLMap/nosqlmap.py"
fi
if [[ -f "${TOOLS_ROOT}/jwt_tool/jwt_tool.py" ]]; then
  write_python_wrapper "jwt_tool" "${TOOLS_ROOT}/jwt_tool/jwt_tool.py"
  link_alias "${BIN_DIR}/jwt_tool" "jwt-tool"
fi
if [[ -f "${TOOLS_ROOT}/XSStrike/xsstrike.py" ]]; then
  write_python_wrapper "xsstrike" "${TOOLS_ROOT}/XSStrike/xsstrike.py"
fi
if [[ -f "${TOOLS_ROOT}/commix/commix.py" ]]; then
  write_python_wrapper "commix" "${TOOLS_ROOT}/commix/commix.py"
fi
if [[ -f "${TOOLS_ROOT}/tplmap/tplmap.py" ]]; then
  write_python_wrapper "tplmap" "${TOOLS_ROOT}/tplmap/tplmap.py"
fi
if [[ -f "${TOOLS_ROOT}/SSRFmap/ssrfmap.py" ]]; then
  write_python_wrapper "ssrfmap" "${TOOLS_ROOT}/SSRFmap/ssrfmap.py"
fi
if [[ -f "${TOOLS_ROOT}/GCPBucketBrute/gcpbucketbrute.py" ]]; then
  write_python_wrapper "gcpbucketbrute" "${TOOLS_ROOT}/GCPBucketBrute/gcpbucketbrute.py"
fi
if [[ -f "${TOOLS_ROOT}/OAuth-Scanner/oauth-scanner.py" ]]; then
  write_python_wrapper "oauth-scanner" "${TOOLS_ROOT}/OAuth-Scanner/oauth-scanner.py"
fi
if [[ -f "${TOOLS_ROOT}/rdp-sec-check/rdp-sec-check.pl" ]]; then
  link_alias "${TOOLS_ROOT}/rdp-sec-check/rdp-sec-check.pl" "rdp-sec-check"
  link_alias "${TOOLS_ROOT}/rdp-sec-check/rdp-sec-check.pl" "rdp-sec-check.pl"
fi
if [[ -f "${TOOLS_ROOT}/testssl.sh/testssl.sh" ]]; then
  link_alias "${TOOLS_ROOT}/testssl.sh/testssl.sh" "testssl.sh"
  link_alias "${TOOLS_ROOT}/testssl.sh/testssl.sh" "testssl"
fi
if [[ -f "${TOOLS_ROOT}/exploitdb/searchsploit" ]]; then
  link_alias "${TOOLS_ROOT}/exploitdb/searchsploit" "searchsploit"
fi
if [[ -f "${TOOLS_ROOT}/graphql-cop/graphql-cop.py" ]]; then
  write_python_wrapper "graphql-cop" "${TOOLS_ROOT}/graphql-cop/graphql-cop.py"
elif [[ -f "${TOOLS_ROOT}/graphql-cop/graphql-cop" ]]; then
  link_alias "${TOOLS_ROOT}/graphql-cop/graphql-cop" "graphql-cop"
fi
if [[ -f "${TOOLS_ROOT}/joomscan/joomscan.pl" ]]; then
  cat > "${BIN_DIR}/joomscan" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exec perl /opt/pentaforge-tools/joomscan/joomscan.pl "$@"
EOF
  chmod +x "${BIN_DIR}/joomscan"
fi
if [[ -f "${TOOLS_ROOT}/PEASS-ng/linPEAS/linpeas.sh" ]]; then
  link_alias "${TOOLS_ROOT}/PEASS-ng/linPEAS/linpeas.sh" "linpeas"
  link_alias "${TOOLS_ROOT}/PEASS-ng/linPEAS/linpeas.sh" "linpeas.sh"
fi
if [[ -f "${TOOLS_ROOT}/firmwalker/firmwalker.sh" ]]; then
  link_alias "${TOOLS_ROOT}/firmwalker/firmwalker.sh" "firmwalker"
fi
if [[ -f "${TOOLS_ROOT}/rdp-sec-check/rdp-sec-check.pl" ]]; then
  cat > "${BIN_DIR}/rdp-sec-check" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exec perl /opt/pentaforge-tools/rdp-sec-check/rdp-sec-check.pl "$@"
EOF
  chmod +x "${BIN_DIR}/rdp-sec-check"
fi
if [[ -f "${TOOLS_ROOT}/kubectx/kubectx" ]]; then
  link_alias "${TOOLS_ROOT}/kubectx/kubectx" "kubectx"
fi
if [[ -f "${TOOLS_ROOT}/kubectx/kubens" ]]; then
  link_alias "${TOOLS_ROOT}/kubectx/kubens" "kubens"
fi

if [[ -d "${TOOLS_ROOT}/CORScanner" ]]; then
  cat > "${BIN_DIR}/CORScanner" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="/opt/pentaforge-tools/CORScanner"
for candidate in \
  "${ROOT}/CORScanner.py" \
  "${ROOT}/corscanner.py" \
  "${ROOT}/cors_scan.py" \
  "${ROOT}/main.py"; do
  if [[ -f "${candidate}" ]]; then
    exec python3 "${candidate}" "$@"
  fi
done
echo "CORScanner repo is present but no runnable entrypoint was found." >&2
exit 1
EOF
  chmod +x "${BIN_DIR}/CORScanner"
  link_alias "${BIN_DIR}/CORScanner" "corscanner"
fi

cat > "${BIN_DIR}/wappalyzer" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

target=""
while (($#)); do
  case "$1" in
    -i|--input|-u|--url)
      target="${2:-}"
      shift 2
      ;;
    -t|--threads|--scan-type)
      if [[ "$1" == "--scan-type" ]]; then
        shift 2
      else
        shift 2
      fi
      ;;
    http://*|https://*)
      target="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "${target}" ]]; then
  echo "Usage: wappalyzer -i <url>" >&2
  exit 2
fi

if command -v wappalyzer-cli >/dev/null 2>&1; then
  exec wappalyzer-cli "${target}"
fi

if [[ -f "/usr/local/lib/node_modules/wappalyzer-cli/index.js" ]]; then
  exec node /usr/local/lib/node_modules/wappalyzer-cli/index.js "${target}"
fi

echo "wappalyzer-cli is not installed." >&2
exit 1
EOF
chmod +x "${BIN_DIR}/wappalyzer"

if command -v proxychains4 >/dev/null 2>&1; then
  link_alias "$(command -v proxychains4)" "proxychains"
fi
if command -v aapt >/dev/null 2>&1; then
  link_alias "$(command -v aapt)" "aapt2"
fi
if command -v retire >/dev/null 2>&1; then
  link_alias "$(command -v retire)" "retire_js"
fi
if command -v kr >/dev/null 2>&1; then
  link_alias "$(command -v kr)" "kiterunner"
fi

cat > "${TOOLS_ROOT}/INSTALL-REPORT.txt" <<EOF
Installed tools:
$(printf '%s\n' "${INSTALLED_TOOLS[@]:-}")

Failed tools:
$(printf '%s\n' "${FAILED_TOOLS[@]:-}")
EOF

if (( ${#FAILED_TOOLS[@]} > 0 )); then
  log "some sandbox tools failed to install:"
  printf '  - %s\n' "${FAILED_TOOLS[@]}"
  if [[ "${STRICT_MODE}" == "1" ]]; then
    exit 1
  fi
fi

log "sandbox toolchain installation complete."
