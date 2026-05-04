"""Curated repository recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_REPOSITORY_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 PASSIVE OSINT & PUBLIC REPO DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "github-search": {
        "t": "passive",
        "c": "public_repo_discovery",
        "u": "curl -s 'https://api.github.com/search/repositories?q=org:TARGET+language:Python' | jq '.items[].name'",
        "d": ["GitHub public repository enumeration", "Language/tech stack filtering", "Star/fork metrics", "Last update correlation", "Topic/tag discovery"],
        "tgt": ["github_public", "tech_stack_enum", "asset_inventory"]
    },
    
    "gitlab-search": {
        "t": "passive",
        "c": "gitlab_project_discovery",
        "u": "curl -s 'https://gitlab.com/api/v4/projects?search=TARGET&per_page=100' | jq '.[].path_with_namespace'",
        "d": ["GitLab public project enumeration", "Visibility level mapping (public/internal)", "Last activity timestamp", "Fork/source correlation", "Topic/tag extraction"],
        "tgt": ["gitlab_public", "project_enum", "asset_inventory"]
    },
    
    "bitbucket-search": {
        "t": "passive",
        "c": "bitbucket_repo_discovery",
        "u": "curl -s -H 'Authorization: Bearer TOKEN' 'https://api.bitbucket.org/2.0/repositories/TEAM?q=name~\"TARGET\"' | jq '.values[].name'",
        "d": ["Bitbucket repository enumeration", "Workspace/team mapping", "Language detection", "Fork relationship discovery", "Last update correlation"],
        "tgt": ["bitbucket_public", "team_enum", "asset_inventory"]
    },
    
    "sourcegraph-code-search": {
        "t": "passive",
        "c": "cross_platform_code_discovery",
        "u": "curl -s 'https://sourcegraph.com/.api/search?q=repo:^github.com/TARGET/.*+file:*.env' | jq",
        "d": ["Cross-repository code search", "File pattern matching", "Language-aware queries", "Public instance enumeration", "Regex-based discovery"],
        "tgt": ["multi_platform", "code_pattern_recon", "config_leak_discovery"]
    },
    
    "grep-app": {
        "t": "passive",
        "c": "github_code_search_gui",
        "u": "# Web: https://grep.app/search?q=org:TARGET+filename:.env",
        "d": ["GitHub code search interface", "Filename/path filtering", "Regex support", "Language filters", "Quick leak discovery"],
        "tgt": ["github_public", "config_leak", "secret_pattern_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🐙 GITHUB-SPECIFIC RECON (Read-Only API)
    # ─────────────────────────────────────────────────────────────
    "gh-cli-recon": {
        "t": "github",
        "c": "cli_based_enumeration",
        "u": "gh repo list TARGET --limit 100 --json name,visibility,updatedAt",
        "d": ["Repository listing via GitHub CLI", "Visibility mapping (public/private)", "Last update timestamp", "Language detection", "Fork/source correlation"],
        "tgt": ["github_org", "repo_inventory", "activity_mapping"]
    },
    
    "github-api-enum": {
        "t": "github",
        "c": "api_resource_enumeration",
        "u": "curl -H 'Authorization: token TOKEN' https://api.github.com/orgs/TARGET/repos?per_page=100 | jq '.[] | {name,visibility,created_at}'",
        "d": ["Full repository metadata extraction", "Branch/tag enumeration", "Collaborator listing", "Webhook configuration discovery", "Deployment environment mapping"],
        "tgt": ["github_org", "api_recon", "metadata_enum"]
    },
    
    "github-branch-enum": {
        "t": "github",
        "c": "branch_tag_discovery",
        "u": "curl -s https://api.github.com/repos/TARGET/REPO/branches | jq '.[].name'",
        "d": ["Branch name enumeration", "Protected branch detection", "Default branch identification", "Tag listing", "Commit SHA correlation"],
        "tgt": ["github_repo", "branch_recon", "version_enum"]
    },
    
    "github-workflow-enum": {
        "t": "github",
        "c": "actions_pipeline_discovery",
        "u": "find .github/workflows -name '*.yml' -exec grep -H 'uses:\\|env:\\|secrets:' {} \\;",
        "d": ["GitHub Actions workflow enumeration", "Third-party action discovery", "Environment variable mapping", "Secret usage patterns", "Trigger event identification"],
        "tgt": ["github_actions", "ci_cd_recon", "pipeline_enum"]
    },
    
    "github-secret-scan-read": {
        "t": "github",
        "c": "public_secret_detection",
        "u": "trufflehog github --org=TARGET --only-verified --json 2>/dev/null",
        "d": ["Public repo secret scanning", "Verified credential detection", "API key pattern matching", "Commit history correlation", "JSON report output"],
        "tgt": ["github_public", "secret_recon", "credential_audit"]
    },
    
    "github-dependency-enum": {
        "t": "github",
        "c": "supply_chain_discovery",
        "u": "curl -s https://api.github.com/repos/TARGET/REPO/dependency-graph/sbom | jq '.dependencies[].package.name' 2>/dev/null",
        "d": ["Dependency graph enumeration", "SBOM extraction", "Package name/version mapping", "License discovery", "Vulnerability correlation (read-only)"],
        "tgt": ["github_repo", "supply_chain_recon", "dependency_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🦊 GITLAB-SPECIFIC RECON (Read-Only API)
    # ─────────────────────────────────────────────────────────────
    "glab-cli-recon": {
        "t": "gitlab",
        "c": "cli_based_enumeration",
        "u": "glab project list --group TARGET --per-page 100 --json name,visibility,created_at",
        "d": ["GitLab project listing via CLI", "Visibility level mapping", "Namespace/group enumeration", "Last activity timestamp", "Fork relationship discovery"],
        "tgt": ["gitlab_group", "project_inventory", "activity_mapping"]
    },
    
    "gitlab-api-enum": {
        "t": "gitlab",
        "c": "api_resource_enumeration",
        "u": "curl -H 'PRIVATE-TOKEN: TOKEN' 'https://gitlab.example.com/api/v4/groups/TARGET/projects?per_page=100' | jq '.[] | {name,visibility,http_url_to_repo}'",
        "d": ["Full project metadata extraction", "Pipeline/job enumeration", "Registry/repository mapping", "Variable name discovery (non-sensitive)", "Webhook configuration"],
        "tgt": ["gitlab_group", "api_recon", "metadata_enum"]
    },
    
    "gitlab-ci-enum": {
        "t": "gitlab",
        "c": "pipeline_config_discovery",
        "u": "curl -s --header 'PRIVATE-TOKEN: TOKEN' 'https://gitlab.example.com/api/v4/projects/ID/repository/files/.gitlab-ci.yml/raw' | grep -E 'script:|image:|variables:'",
        "d": [".gitlab-ci.yml enumeration", "Job/stage mapping", "Runner tag discovery", "Variable name extraction", "Image/executor identification"],
        "tgt": ["gitlab_ci", "pipeline_recon", "config_audit"]
    },
    
    "gitlab-registry-enum": {
        "t": "gitlab",
        "c": "container_registry_discovery",
        "u": "curl -s --header 'PRIVATE-TOKEN: TOKEN' 'https://gitlab.example.com/api/v4/projects/ID/registry/repositories' | jq '.[].path'",
        "d": ["Container registry repository listing", "Image tag enumeration", "Last update timestamp", "Size metadata", "Access level mapping"],
        "tgt": ["gitlab_registry", "container_recon", "image_inventory"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🪶 BITBUCKET & GITEA RECON
    # ─────────────────────────────────────────────────────────────
    "bitbucket-api-enum": {
        "t": "bitbucket",
        "c": "api_resource_enumeration",
        "u": "curl -s -H 'Authorization: Bearer TOKEN' 'https://api.bitbucket.org/2.0/repositories/TEAM?pagelen=50' | jq '.values[].name'",
        "d": ["Repository enumeration", "Workspace/team mapping", "Language detection", "Fork/source correlation", "Last update timestamp"],
        "tgt": ["bitbucket_team", "repo_inventory", "metadata_enum"]
    },
    
    "gitea-api-enum": {
        "t": "gitea",
        "c": "self_hosted_enumeration",
        "u": "curl -s 'https://gitea.example.com/api/v1/orgs/TARGET/repos' | jq '.[].name'",
        "d": ["Self-hosted Gitea repo enumeration", "Organization mapping", "Visibility level discovery", "Clone URL extraction", "Last push timestamp"],
        "tgt": ["gitea_self_hosted", "org_recon", "asset_inventory"]
    },
    
    "forgejo-recon": {
        "t": "forgejo",
        "c": "fedicated_git_enum",
        "u": "curl -s 'https://forgejo.example.com/api/v1/users/TARGET/repos' | jq '.[].full_name'",
        "d": ["Forgejo repository enumeration", "User/org mapping", "Mirror relationship discovery", "SSH/HTTP clone URL extraction", "Activity correlation"],
        "tgt": ["forgejo", "user_recon", "mirror_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 SECRET DETECTION (READ-ONLY SCAN MODE)
    # ─────────────────────────────────────────────────────────────
    "gitleaks-detect": {
        "t": "secret_scan",
        "c": "pattern_based_credential_discovery",
        "u": "gitleaks detect --source=./repo --report-format json --report-path leaks.json --no-git",
        "d": ["Regex-based secret pattern matching", "High-entropy string detection", "Config file scanning", "JSON/CSV report output", "False positive filtering"],
        "tgt": ["local_repo", "secret_recon", "credential_audit"]
    },
    
    "trufflehog-filesystem": {
        "t": "secret_scan",
        "c": "verified_secret_detection",
        "u": "trufflehog filesystem ./repo --only-verified --json --no-update",
        "d": ["Verified credential detection", "API key validation", "Private key identification", "Commit history correlation", "Structured JSON output"],
        "tgt": ["local_repo", "verified_secrets", "high_confidence_findings"]
    },
    
    "detect-secrets": {
        "t": "secret_scan",
        "c": "baseline_secret_audit",
        "u": "detect-secrets scan ./repo --baseline .secrets.baseline",
        "d": ["Baseline-based secret tracking", "Plugin architecture (AWS/Azure/GCP)", "False positive suppression", "Pre-commit integration", "Audit workflow support"],
        "tgt": ["local_repo", "baseline_audit", "ci_integration"]
    },
    
    "repo-supervisor": {
        "t": "secret_scan",
        "c": "lightweight_secret_hunt",
        "u": "repo-supervisor -d ./repo -o results.txt",
        "d": ["Fast regex-based scanning", "Low memory footprint", "Multiple secret patterns", "Output filtering", "CI/CD friendly"],
        "tgt": ["local_repo", "quick_scan", "resource_constrained"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📦 DEPENDENCY & SUPPLY CHAIN RECON
    # ─────────────────────────────────────────────────────────────
    "trivy-repo": {
        "t": "supply_chain",
        "c": "repo_vulnerability_scanning",
        "u": "trivy repo ./repo --severity HIGH,CRITICAL --format json --output vulns.json",
        "d": ["Repository-wide vulnerability scanning", "Language-agnostic detection", "CVE/CVSS mapping", "Fix version discovery", "SBOM generation"],
        "tgt": ["local_repo", "vuln_recon", "supply_chain_audit"]
    },
    
    "grype-repo": {
        "t": "supply_chain",
        "c": "dependency_vulnerability_enum",
        "u": "grype dir:./repo --output json --only-fixed",
        "d": ["Directory-based scanning", "Package enumeration", "CVE correlation", "Fixed version mapping", "Match type classification"],
        "tgt": ["local_repo", "dependency_recon", "fix_priority"]
    },
    
    "syft-sbom": {
        "t": "supply_chain",
        "c": "software_bill_of_materials",
        "u": "syft ./repo -o spdx-json > sbom.json",
        "d": ["SBOM generation (SPDX/CycloneDX)", "Package inventory extraction", "License enumeration", "PURL/CPE mapping", "Multi-language support"],
        "tgt": ["local_repo", "sbom_generation", "compliance_recon"]
    },
    
    "osv-scanner": {
        "t": "supply_chain",
        "c": "osv_database_correlation",
        "u": "osv-scanner -r ./repo --format json",
        "d": ["OSV.dev database correlation", "Lockfile parsing", "Vulnerability ID mapping", "Ecosystem support (npm/pip/cargo)", "CI/CD integration"],
        "tgt": ["local_repo", "osv_recon", "multi_ecosystem"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔁 CI/CD PIPELINE & WORKFLOW DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "github-actions-audit": {
        "t": "ci_cd",
        "c": "workflow_security_recon",
        "u": "find .github/workflows -name '*.yml' -exec yq eval '.jobs.*.steps[].uses' {} \\; | sort -u",
        "d": ["Third-party action enumeration", "Action version pinning audit", "Permission scope mapping", "Environment variable discovery", "Trigger event analysis"],
        "tgt": ["github_actions", "workflow_audit", "action_enum"]
    },
    
    "gitlab-ci-audit": {
        "t": "ci_cd",
        "c": "pipeline_config_recon",
        "u": "find . -name '.gitlab-ci.yml' -exec yq eval '.stages, .variables' {} \\;",
        "d": ["Stage/job enumeration", "Variable name extraction", "Runner tag discovery", "Image/executor mapping", "Artifact configuration audit"],
        "tgt": ["gitlab_ci", "pipeline_recon", "config_enum"]
    },
    
    "circleci-config-enum": {
        "t": "ci_cd",
        "c": "circleci_workflow_discovery",
        "u": "find . -name 'config.yml' -path '*/.circleci/*' -exec yq eval '.jobs.*.steps' {} \\;",
        "d": ["Job/step enumeration", "Executor type discovery", "Context/variable name mapping", "Orb usage detection", "Workflow dependency mapping"],
        "tgt": ["circleci", "workflow_recon", "orb_enum"]
    },
    
    "jenkinsfile-audit": {
        "t": "ci_cd",
        "c": "jenkins_pipeline_recon",
        "u": "find . -name 'Jenkinsfile' -exec grep -H 'sh\\|withCredentials\\|credentialsId' {} \\;",
        "d": ["Pipeline step enumeration", "Credential reference discovery", "Shell command extraction", "Agent/label mapping", "Post-action configuration"],
        "tgt": ["jenkins", "pipeline_recon", "credential_ref_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔎 CODE SEARCH & PATTERN MATCHING
    # ─────────────────────────────────────────────────────────────
    "ripgrep-repo": {
        "t": "code_search",
        "c": "fast_regex_code_hunt",
        "u": "rg -i 'api[_-]?key|password|secret|token' ./repo --type-add 'env:*.env' -t env -t json -t yaml",
        "d": ["Fast regex-based code search", "File type filtering", "Case-insensitive matching", "Context extraction", "Binary file exclusion"],
        "tgt": ["local_repo", "pattern_recon", "quick_search"]
    },
    
    "git-grep-pattern": {
        "t": "code_search",
        "c": "git_aware_pattern_search",
        "u": "git grep -i 'TODO|FIXME|HACK|XXX' -- '*.js' '*.py' '*.go'",
        "d": ["Git-aware pattern matching", "Branch/tag scoped search", "File extension filtering", "Line number output", "Commit correlation ready"],
        "tgt": ["git_repo", "code_quality_recon", "tech_debt_enum"]
    },
    
    "codeql-query-recon": {
        "t": "code_search",
        "c": "semantic_code_analysis",
        "u": "codeql database create ./db --language=python --source-root=./repo && codeql query run ./queries.ql --database=./db",
        "d": ["Semantic code analysis", "Data flow tracking", "Vulnerability pattern matching", "Multi-language support", "Custom query development"],
        "tgt": ["local_repo", "semantic_recon", "advanced_analysis"]
    },
    
    "semgrep-repo-scan": {
        "t": "code_search",
        "c": "pattern_based_security_scan",
        "u": "semgrep --config=auto --json --output findings.json ./repo",
        "d": ["Pattern-based security scanning", "Community rule library", "Custom rule support", "Multi-language parsing", "CI/CD integration"],
        "tgt": ["local_repo", "security_recon", "rule_based_audit"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌿 BRANCH/TAG/COMMIT ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "git-branch-enum": {
        "t": "git_meta",
        "c": "branch_tag_discovery",
        "u": "git branch -a; git tag -l; git log --oneline --all -20",
        "d": ["Local/remote branch enumeration", "Tag listing", "Recent commit history", "Author/date correlation", "Merge pattern analysis"],
        "tgt": ["git_repo", "version_enum", "activity_recon"]
    },
    
    "git-remote-enum": {
        "t": "git_meta",
        "c": "remote_repository_mapping",
        "u": "git remote -v; git config --get-regexp 'remote\\..*\\.url'",
        "d": ["Remote URL enumeration", "Fetch/push URL discovery", "SSH/HTTP protocol mapping", "Upstream correlation", "Mirror relationship detection"],
        "tgt": ["git_repo", "remote_recon", "mirror_enum"]
    },
    
    "git-submodule-enum": {
        "t": "git_meta",
        "c": "dependency_repository_discovery",
        "u": "git submodule status --recursive; cat .gitmodules 2>/dev/null",
        "d": ["Submodule enumeration", "External repo URL extraction", "Commit pin discovery", "Path mapping", "Recursive dependency mapping"],
        "tgt": ["git_repo", "submodule_recon", "supply_chain_enum"]
    },
    
    "git-lfs-enum": {
        "t": "git_meta",
        "c": "large_file_storage_discovery",
        "u": "git lfs ls-files; cat .gitattributes 2>/dev/null | grep lfs",
        "d": ["Git LFS file enumeration", "Pointer file discovery", "Storage backend inference", "Size/metadata extraction", "Access pattern analysis"],
        "tgt": ["git_lfs", "large_file_recon", "storage_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 👥 ORGANIZATION & USER MAPPING
    # ─────────────────────────────────────────────────────────────
    "github-org-enum": {
        "t": "org_user",
        "c": "github_membership_discovery",
        "u": "curl -s https://api.github.com/orgs/TARGET/members?per_page=100 | jq '.[].login'",
        "d": ["Organization member enumeration", "Role mapping (member/admin)", "Avatar/URL extraction", "Public activity correlation", "Team membership inference"],
        "tgt": ["github_org", "user_enum", "social_recon"]
    },
    
    "gitlab-user-enum": {
        "t": "org_user",
        "c": "gitlab_membership_discovery",
        "u": "curl -s --header 'PRIVATE-TOKEN: TOKEN' 'https://gitlab.example.com/api/v4/groups/TARGET/members?per_page=100' | jq '.[].username'",
        "d": ["Group member enumeration", "Access level mapping (guest/developer/maintainer)", "Last activity timestamp", "Avatar/URL extraction", "Bot account detection"],
        "tgt": ["gitlab_group", "user_enum", "access_audit"]
    },
    
    "repo-contributor-map": {
        "t": "org_user",
        "c": "contribution_analysis",
        "u": "git log --all --format='%ae' | sort | uniq -c | sort -rn | head -20",
        "d": ["Contributor email enumeration", "Commit frequency mapping", "Author activity correlation", "Domain-based grouping", "Key developer identification"],
        "tgt": ["git_repo", "contributor_recon", "team_mapping"]
    },
    
    "github-team-enum": {
        "t": "org_user",
        "c": "team_structure_discovery",
        "u": "curl -H 'Authorization: token TOKEN' https://api.github.com/orgs/TARGET/teams | jq '.[] | {name,slug,privacy,permission}'",
        "d": ["Team enumeration", "Privacy level mapping (secret/visible)", "Permission scope discovery", "Member count inference", "Parent/child team mapping"],
        "tgt": ["github_org", "team_recon", "permission_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🗄️ EXPOSED .GIT & BACKUP DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "git-dumper": {
        "t": "exposed_git",
        "c": "public_git_directory_enum",
        "u": "python3 git-dumper.py https://TARGET/.git ./dump",
        "d": ["Exposed .git directory detection", "Object file enumeration", "Commit history reconstruction", "File recovery capability", "Read-only mode available"],
        "tgt": ["exposed_git", "web_recon", "backup_discovery"]
    },
    
    "diggit": {
        "t": "exposed_git",
        "c": "git_repo_harvesting",
        "u": "diggit -u https://TARGET/.git/ -o output/",
        "d": ["Git repository harvesting from web", "HEAD/refs parsing", "Blob/tree extraction", "Commit metadata recovery", "Parallel download support"],
        "tgt": ["exposed_git", "web_recon", "forensic_enum"]
    },
    
    "gittools-findgit": {
        "t": "exposed_git",
        "c": "git_artifact_discovery",
        "u": "find ./target -name '.git' -o -name 'objects' -o -name 'refs' 2>/dev/null",
        "d": ["Filesystem-based .git discovery", "Git artifact pattern matching", "Directory structure analysis", "Partial repo detection", "Forensic enumeration"],
        "tgt": ["filesystem", "backup_recon", "artifact_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "repo-recon-pipeline": {
        "t": "automation",
        "c": "multi_platform_toolchain",
        "u": "# Your script: github-api-enum | gitleaks | trivy repo | semgrep --output report.json",
        "d": ["Cross-platform repository enumeration", "Secret scanning integration", "Vulnerability correlation", "Report aggregation", "CI/CD pipeline embedding"],
        "tgt": ["multi_platform", "automated_recon", "continuous_audit"]
    },
    
    "docker-repo-recon": {
        "t": "automation",
        "c": "containerized_toolchain",
        "u": "docker run -v $(pwd):/repo ghcr.io/gitleaks/gitleaks detect --source=/repo --report-path /data/leaks.json",
        "d": ["Reproducible repo recon environments", "Version-pinned tools", "Clean workspaces", "Pre-configured scanning profiles", "No host pollution"],
        "tgt": ["all", "lab", "client_deliverables", "compliance_audits"]
    },
    
    "custom-repo-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your Python/Go script: Query repo APIs → Correlate secrets/dependencies → Generate risk graph",
        "d": ["Custom API integrations", "Asset correlation logic", "Risk graph generation", "Supply chain mapping", "Structured output (JSON/GraphML)"],
        "tgt": ["enterprise", "red_team", "client_specific", "large_orgs"]
    }
}

REPOSITORY_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_REPOSITORY_RECON_TOOLS)

network_tools = REPOSITORY_RECON_TOOLS
