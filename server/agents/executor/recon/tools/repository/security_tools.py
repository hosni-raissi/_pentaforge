"""Curated repository recon security tool catalog for `run_custom` usage."""
from __future__ import annotations

from server.agents.executor.recon.tools.security_catalog import normalize_security_catalog

_RAW_REPOSITORY_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 PASSIVE OSINT & PUBLIC REPO DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "github-search": {
        "t": "passive",
        "c": "public_repo_discovery",
        "u": "curl -s 'https://api.github.com/search/repositories?q=org:TARGET+language:Python' 2>/dev/null | jq -r '.items[]?.name?'",
        "d": ["GitHub public repository enumeration", "Language/tech stack filtering", "Star/fork metrics", "Last update correlation"],
        "tgt": ["github_public", "tech_stack_enum", "asset_inventory"],
        "note": "Public API; rate-limited. Add -H 'Authorization: token (SECRET:github)' for higher limits"
    },
    
    "gitlab-search": {
        "t": "passive",
        "c": "gitlab_project_discovery",
        "u": "curl -s 'https://gitlab.com/api/v4/projects?search=TARGET&per_page=100' 2>/dev/null | jq -r '.[]?.path_with_namespace?'",
        "d": ["GitLab public project enumeration", "Visibility level mapping", "Last activity timestamp", "Fork/source correlation"],
        "tgt": ["gitlab_public", "project_enum", "asset_inventory"]
    },
    
    "bitbucket-search": {
        "t": "passive",
        "c": "bitbucket_repo_discovery",
        "u": "curl -s -H 'Authorization: Bearer (SECRET:bitbucket)' 'https://api.bitbucket.org/2.0/repositories/TEAM?q=name~\"TARGET\"' 2>/dev/null | jq -r '.values[]?.name?'",
        "d": ["Bitbucket repository enumeration", "Workspace/team mapping", "Language detection", "Fork relationship discovery"],
        "tgt": ["bitbucket_public", "team_enum", "asset_inventory"],
        "note": "(SECRET:bitbucket) injected at runtime; OAuth token required"
    },
    
    "sourcegraph-code-search": {
        "t": "passive",
        "c": "cross_platform_code_discovery",
        "u": "curl -s 'https://sourcegraph.com/.api/search?q=repo:^github.com/TARGET/.*+file:*.env' 2>/dev/null | jq -r '.results[]?.repository?.name?'",
        "d": ["Cross-repository code search", "File pattern matching", "Language-aware queries", "Regex-based discovery"],
        "tgt": ["multi_platform", "code_pattern_recon", "config_leak_discovery"]
    },
    
    "grep-app": {
        "t": "passive",
        "c": "github_code_search_gui",
        "u": "# Web: https://grep.app/search?q=org:TARGET+filename:.env — use API endpoint if available",
        "d": ["GitHub code search interface", "Filename/path filtering", "Regex support", "Quick leak discovery"],
        "tgt": ["github_public", "config_leak", "secret_pattern_recon"],
        "note": "Interactive web UI; consider scraping API if rate limits allow"
    },

    # ─────────────────────────────────────────────────────────────
    # 🐙 GITHUB-SPECIFIC RECON (Read-Only API)
    # ─────────────────────────────────────────────────────────────
    "gh-cli-recon": {
        "t": "github",
        "c": "cli_based_enumeration",
        "u": "gh repo list TARGET --limit 100 --json name,visibility,updatedAt 2>/dev/null | jq -r '.[]?.name?'",
        "d": ["Repository listing via GitHub CLI", "Visibility mapping", "Last update timestamp", "Language detection"],
        "tgt": ["github_org", "repo_inventory", "activity_mapping"],
        "note": "Requires gh auth login or GITHUB_TOKEN env var"
    },
    
    "github-api-enum": {
        "t": "github",
        "c": "api_resource_enumeration",
        "u": "curl -H 'Authorization: token (SECRET:github)' -s 'https://api.github.com/orgs/TARGET/repos?per_page=100' 2>/dev/null | jq -r '.[] | {name,visibility,created_at}'?",
        "d": ["Full repository metadata extraction", "Branch/tag enumeration", "Collaborator listing", "Webhook configuration discovery"],
        "tgt": ["github_org", "api_recon", "metadata_enum"],
        "note": "(SECRET:github) injected at runtime; respect rate limits"
    },
    
    "github-branch-enum": {
        "t": "github",
        "c": "branch_tag_discovery",
        "u": "curl -s 'https://api.github.com/repos/TARGET/REPO/branches' 2>/dev/null | jq -r '.[]?.name?'",
        "d": ["Branch name enumeration", "Protected branch detection", "Default branch identification", "Tag listing"],
        "tgt": ["github_repo", "branch_recon", "version_enum"]
    },
    
    "github-workflow-enum": {
        "t": "github",
        "c": "actions_pipeline_discovery",
        "u": "echo '(MANIFEST:workflows)' | grep -E 'uses:|env:|secrets:' - 2>/dev/null | sort -u",
        "d": ["GitHub Actions workflow enumeration", "Third-party action discovery", "Environment variable mapping", "Secret usage patterns"],
        "tgt": ["github_actions", "ci_cd_recon", "pipeline_enum"],
        "note": "(MANIFEST:workflows) piped via stdin; grep reads from -"
    },
    
    "github-secret-scan-read": {
        "t": "github",
        "c": "public_secret_detection",
        "u": "trufflehog github --org=TARGET --only-verified --json --no-update 2>/dev/null | jq -c '.[]?'",
        "d": ["Public repo secret scanning", "Verified credential detection", "API key pattern matching", "Commit history correlation"],
        "tgt": ["github_public", "secret_recon", "credential_audit"],
        "note": "Requires GITHUB_TOKEN env var; --no-update avoids local cache writes"
    },
    
    "github-dependency-enum": {
        "t": "github",
        "c": "supply_chain_discovery",
        "u": "curl -s -H 'Authorization: token (SECRET:github)' 'https://api.github.com/repos/TARGET/REPO/dependency-graph/sbom' 2>/dev/null | jq -r '.dependencies[]?.package?.name?'",
        "d": ["Dependency graph enumeration", "SBOM extraction", "Package name/version mapping", "License discovery"],
        "tgt": ["github_repo", "supply_chain_recon", "dependency_audit"],
        "note": "(SECRET:github) injected; SBOM endpoint requires repo access"
    },

    # ─────────────────────────────────────────────────────────────
    # 🦊 GITLAB-SPECIFIC RECON (Read-Only API)
    # ─────────────────────────────────────────────────────────────
    "glab-cli-recon": {
        "t": "gitlab",
        "c": "cli_based_enumeration",
        "u": "glab project list --group TARGET --per-page 100 --json name,visibility,created_at 2>/dev/null | jq -r '.[]?.name?'",
        "d": ["GitLab project listing via CLI", "Visibility level mapping", "Namespace/group enumeration", "Last activity timestamp"],
        "tgt": ["gitlab_group", "project_inventory", "activity_mapping"],
        "note": "Requires glab auth login or GITLAB_TOKEN env var"
    },
    
    "gitlab-api-enum": {
        "t": "gitlab",
        "c": "api_resource_enumeration",
        "u": "curl -H 'PRIVATE-TOKEN: (SECRET:gitlab)' -s 'https://gitlab.example.com/api/v4/groups/TARGET/projects?per_page=100' 2>/dev/null | jq -r '.[] | {name,visibility,http_url_to_repo}'?",
        "d": ["Full project metadata extraction", "Pipeline/job enumeration", "Registry/repository mapping", "Variable name discovery"],
        "tgt": ["gitlab_group", "api_recon", "metadata_enum"],
        "note": "(SECRET:gitlab) injected at runtime; adjust URL for self-hosted instances"
    },
    
    "gitlab-ci-enum": {
        "t": "gitlab",
        "c": "pipeline_config_discovery",
        "u": "curl -s --header 'PRIVATE-TOKEN: (SECRET:gitlab)' 'https://gitlab.example.com/api/v4/projects/ID/repository/files/.gitlab-ci.yml/raw' 2>/dev/null | grep -E 'script:|image:|variables:'",
        "d": [".gitlab-ci.yml enumeration", "Job/stage mapping", "Runner tag discovery", "Variable name extraction"],
        "tgt": ["gitlab_ci", "pipeline_recon", "config_audit"],
        "note": "Replace ID with project_id; (SECRET:gitlab) injected at runtime"
    },
    
    "gitlab-registry-enum": {
        "t": "gitlab",
        "c": "container_registry_discovery",
        "u": "curl -s --header 'PRIVATE-TOKEN: (SECRET:gitlab)' 'https://gitlab.example.com/api/v4/projects/ID/registry/repositories' 2>/dev/null | jq -r '.[]?.path?'",
        "d": ["Container registry repository listing", "Image tag enumeration", "Last update timestamp", "Access level mapping"],
        "tgt": ["gitlab_registry", "container_recon", "image_inventory"],
        "note": "Requires project ID and token; adjust URL for self-hosted"
    },

    # ─────────────────────────────────────────────────────────────
    # 🪶 BITBUCKET & GITEA RECON
    # ─────────────────────────────────────────────────────────────
    "bitbucket-api-enum": {
        "t": "bitbucket",
        "c": "api_resource_enumeration",
        "u": "curl -s -H 'Authorization: Bearer (SECRET:bitbucket)' 'https://api.bitbucket.org/2.0/repositories/TEAM?pagelen=50' 2>/dev/null | jq -r '.values[]?.name?'",
        "d": ["Repository enumeration", "Workspace/team mapping", "Language detection", "Fork/source correlation"],
        "tgt": ["bitbucket_team", "repo_inventory", "metadata_enum"],
        "note": "(SECRET:bitbucket) injected; OAuth 2.0 token required"
    },
    
    "gitea-api-enum": {
        "t": "gitea",
        "c": "self_hosted_enumeration",
        "u": "curl -s 'https://gitea.example.com/api/v1/orgs/TARGET/repos' 2>/dev/null | jq -r '.[]?.name?'",
        "d": ["Self-hosted Gitea repo enumeration", "Organization mapping", "Visibility level discovery", "Clone URL extraction"],
        "tgt": ["gitea_self_hosted", "org_recon", "asset_inventory"]
    },
    
    "forgejo-recon": {
        "t": "forgejo",
        "c": "fedicated_git_enum",
        "u": "curl -s 'https://forgejo.example.com/api/v1/users/TARGET/repos' 2>/dev/null | jq -r '.[]?.full_name?'",
        "d": ["Forgejo repository enumeration", "User/org mapping", "Mirror relationship discovery", "SSH/HTTP clone URL extraction"],
        "tgt": ["forgejo", "user_recon", "mirror_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔎 CODE SEARCH & PATTERN MATCHING
    # ─────────────────────────────────────────────────────────────
    "ripgrep-repo": {
        "t": "code_search",
        "c": "fast_regex_code_hunt",
        "u": "rg -i 'api[_-]?key|password|secret|token' --type-add 'env:*.env' -t env -t json -t yaml (CONFIG:repo_path)",
        "d": ["Fast regex-based code search", "File type filtering", "Case-insensitive matching", "Context extraction"],
        "tgt": ["local_repo", "pattern_recon", "quick_search"],
        "note": "(CONFIG:repo_path) resolves to the local repository checkout"
    },
    
    "git-grep-pattern": {
        "t": "code_search",
        "c": "git_aware_pattern_search",
        "u": "git grep -i 'TODO|FIXME|HACK|XXX' -- '*.js' '*.py' '*.go' 2>/dev/null | head -30",
        "d": ["Git-aware pattern matching", "Branch/tag scoped search", "File extension filtering", "Line number output"],
        "tgt": ["git_repo", "code_quality_recon", "tech_debt_enum"],
        "note": "Requires git repo in current directory; head limits output for streaming"
    },
    
    "codeql-query-recon": {
        "t": "code_search",
        "c": "semantic_code_analysis",
        "u": "# Interactive: codeql database create ./db --language=python --source-root=(CONFIG:repo_path) && codeql query run (CONFIG:query) --database=./db --format=json",
        "d": ["Semantic code analysis", "Data flow tracking", "Vulnerability pattern matching", "Custom query development"],
        "tgt": ["local_repo", "semantic_recon", "advanced_analysis"],
        "note": "Requires local DB creation; use (CONFIG:repo_path) and (CONFIG:query) placeholders; JSON output to stdout"
    },
    
    "semgrep-repo-scan": {
        "t": "code_search",
        "c": "pattern_based_security_scan",
        "u": "semgrep --config=auto --json (CONFIG:repo_path)",
        "d": ["Pattern-based security scanning", "Community rule library", "Custom rule support", "JSON to stdout"],
        "tgt": ["local_repo", "security_recon", "rule_based_audit"],
        "note": "(CONFIG:repo_path) resolves to the local repository checkout"
    },

    # ─────────────────────────────────────────────────────────────
    # 🌿 BRANCH/TAG/COMMIT ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "git-branch-enum": {
        "t": "git_meta",
        "c": "branch_tag_discovery",
        "u": "git -C (CONFIG:repo_path) branch -a 2>/dev/null; git -C (CONFIG:repo_path) tag -l 2>/dev/null; git -C (CONFIG:repo_path) log --oneline --all -20 2>/dev/null",
        "d": ["Local/remote branch enumeration", "Tag listing", "Recent commit history", "Author/date correlation"],
        "tgt": ["git_repo", "version_enum", "activity_recon"],
        "note": "(CONFIG:repo_path) resolves to repo directory; git -C avoids cd"
    },
    
    "git-remote-enum": {
        "t": "git_meta",
        "c": "remote_repository_mapping",
        "u": "git -C (CONFIG:repo_path) remote -v 2>/dev/null; git -C (CONFIG:repo_path) config --get-regexp 'remote\\..*\\.url' 2>/dev/null",
        "d": ["Remote URL enumeration", "Fetch/push URL discovery", "SSH/HTTP protocol mapping", "Upstream correlation"],
        "tgt": ["git_repo", "remote_recon", "mirror_enum"],
        "note": "(CONFIG:repo_path) resolves to repo directory"
    },
    
    "git-submodule-enum": {
        "t": "git_meta",
        "c": "dependency_repository_discovery",
        "u": "git -C (CONFIG:repo_path) submodule status --recursive 2>/dev/null; cat (CONFIG:repo_path)/.gitmodules 2>/dev/null | grep -v '^#'",
        "d": ["Submodule enumeration", "External repo URL extraction", "Commit pin discovery", "Path mapping"],
        "tgt": ["git_repo", "submodule_recon", "supply_chain_enum"],
        "note": "(CONFIG:repo_path) resolves to repo directory; .gitmodules read directly"
    },
    
    "git-lfs-enum": {
        "t": "git_meta",
        "c": "large_file_storage_discovery",
        "u": "git -C (CONFIG:repo_path) lfs ls-files 2>/dev/null; cat (CONFIG:repo_path)/.gitattributes 2>/dev/null | grep lfs",
        "d": ["Git LFS file enumeration", "Pointer file discovery", "Storage backend inference", "Size/metadata extraction"],
        "tgt": ["git_lfs", "large_file_recon", "storage_enum"],
        "note": "(CONFIG:repo_path) resolves to repo directory; requires git-lfs installed"
    },

    # ─────────────────────────────────────────────────────────────
    # 👥 ORGANIZATION & USER MAPPING
    # ─────────────────────────────────────────────────────────────
    "github-org-enum": {
        "t": "org_user",
        "c": "github_membership_discovery",
        "u": "curl -s 'https://api.github.com/orgs/TARGET/members?per_page=100' 2>/dev/null | jq -r '.[]?.login?'",
        "d": ["Organization member enumeration", "Role mapping", "Avatar/URL extraction", "Public activity correlation"],
        "tgt": ["github_org", "user_enum", "social_recon"],
        "note": "Public API; add -H 'Authorization: token (SECRET:github)' for private orgs"
    },
    
    "gitlab-user-enum": {
        "t": "org_user",
        "c": "gitlab_membership_discovery",
        "u": "curl -s --header 'PRIVATE-TOKEN: (SECRET:gitlab)' 'https://gitlab.example.com/api/v4/groups/TARGET/members?per_page=100' 2>/dev/null | jq -r '.[]?.username?'",
        "d": ["Group member enumeration", "Access level mapping", "Last activity timestamp", "Bot account detection"],
        "tgt": ["gitlab_group", "user_enum", "access_audit"],
        "note": "(SECRET:gitlab) injected; adjust URL for self-hosted instances"
    },
    
    "repo-contributor-map": {
        "t": "org_user",
        "c": "contribution_analysis",
        "u": "git -C (CONFIG:repo_path) log --all --format='%ae' 2>/dev/null | sort | uniq -c | sort -rn | head -20",
        "d": ["Contributor email enumeration", "Commit frequency mapping", "Author activity correlation", "Key developer identification"],
        "tgt": ["git_repo", "contributor_recon", "team_mapping"],
        "note": "(CONFIG:repo_path) resolves to repo directory; head limits output"
    },
    
    "github-team-enum": {
        "t": "org_user",
        "c": "team_structure_discovery",
        "u": "curl -H 'Authorization: token (SECRET:github)' -s 'https://api.github.com/orgs/TARGET/teams' 2>/dev/null | jq -r '.[] | {name,slug,privacy,permission}'?",
        "d": ["Team enumeration", "Privacy level mapping", "Permission scope discovery", "Member count inference"],
        "tgt": ["github_org", "team_recon", "permission_enum"],
        "note": "(SECRET:github) injected; requires org admin or team read scope"
    },

    # ─────────────────────────────────────────────────────────────
    # 🗄️ EXPOSED .GIT & BACKUP DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "git-dumper": {
        "t": "exposed_git",
        "c": "public_git_directory_enum",
        "u": "python3 git-dumper.py https://TARGET/.git - 2>/dev/null | grep -E '^\\[\\+\\]|extracted'",
        "d": ["Exposed .git directory detection", "Object file enumeration", "Commit history reconstruction", "Read-only mode"],
        "tgt": ["exposed_git", "web_recon", "backup_discovery"],
        "note": "May require patching git-dumper for stdout output; - for output dir streams to stdout"
    },
    
    "diggit": {
        "t": "exposed_git",
        "c": "git_repo_harvesting",
        "u": "diggit -u https://TARGET/.git/ -o - 2>/dev/null | grep -E '^\\[\\+\\]|downloaded'",
        "d": ["Git repository harvesting from web", "HEAD/refs parsing", "Blob/tree extraction", "Parallel download"],
        "tgt": ["exposed_git", "web_recon", "forensic_enum"],
        "note": "-o - outputs to stdout; may require tool modification for stream support"
    },
    
    "gittools-findgit": {
        "t": "exposed_git",
        "c": "git_artifact_discovery",
        "u": "find (CONFIG:target_path) -name '.git' -o -name 'objects' -o -name 'refs' 2>/dev/null | head -30",
        "d": ["Filesystem-based .git discovery", "Git artifact pattern matching", "Directory structure analysis", "Partial repo detection"],
        "tgt": ["filesystem", "backup_recon", "artifact_enum"],
        "note": "(CONFIG:target_path) resolves to scan directory; head limits verbose output"
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "repo-recon-pipeline": {
        "t": "automation",
        "c": "multi_platform_toolchain",
        "u": "# Chain via pipes: echo '(MANIFEST:repo)' | gitleaks detect --source=- --json | jq -c '.[]?' | trivy repo - --format json",
        "d": ["Cross-platform repository enumeration", "Secret scanning integration", "Vulnerability correlation", "JSON to stdout"],
        "tgt": ["multi_platform", "automated_recon", "continuous_audit"]
    },
    
    "docker-repo-recon": {
        "t": "automation",
        "c": "containerized_toolchain",
        "u": "echo '(MANIFEST:repo)' | docker run --rm -i ghcr.io/gitleaks/gitleaks:latest detect --source=- --report-format json --report-path - 2>/dev/null | jq -c '.[]?'",
        "d": ["Reproducible repo recon environments", "Version-pinned tools", "JSON output to stdout", "No host pollution"],
        "tgt": ["all", "lab", "client_deliverables", "compliance_audits"],
        "note": "(MANIFEST:repo) piped via stdin; --source=- and --report-path=- enable streaming"
    },
    
    "custom-repo-mapper": {
        "t": "automation",
        "c": "engagement_specific_orchestration",
        "u": "# Your script: Query repo APIs → Correlate secrets/dependencies → Output JSON to stdout",
        "d": ["Custom API integrations", "Asset correlation logic", "Risk graph generation", "Structured JSON output"],
        "tgt": ["enterprise", "red_team", "client_specific", "large_orgs"]
    }
}

REPOSITORY_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_REPOSITORY_RECON_TOOLS)

# ✅ Correct alias for consistency with other catalogs
repo_tools = REPOSITORY_RECON_TOOLS
