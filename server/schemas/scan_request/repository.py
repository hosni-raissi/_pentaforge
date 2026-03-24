
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class RepoInputType(str, Enum):
    github      = "github"
    gitlab      = "gitlab"
    bitbucket   = "bitbucket"
    local       = "local"       # uploaded zip

class Language(str, Enum):
    python      = "python"
    javascript  = "javascript"
    typescript  = "typescript"
    java        = "java"
    csharp      = "csharp"
    php         = "php"
    go          = "go"
    ruby        = "ruby"
    rust        = "rust"
    cpp         = "cpp"
    c           = "c"

class Framework(str, Enum):
    fastapi     = "fastapi"
    django      = "django"
    flask       = "flask"
    express     = "express"
    nestjs      = "nestjs"
    nextjs      = "nextjs"
    spring      = "spring"
    laravel     = "laravel"
    rails       = "rails"

class RepoAuthConfig(BaseModel):
    token:          Optional[str]  = None       # GitHub/GitLab PAT
    ssh_key:        Optional[str]  = None

class RepositoryScanRequest(BaseModel):
    # --- Source ---
    input_type:         RepoInputType
    repo_url:           Optional[str]  = None
    file_path:          Optional[str]  = None   # local zip upload
    branch:             Optional[str]  = "main"
    auth:               Optional[RepoAuthConfig] = None

    # --- Code context ---
    language:           Optional[List[Language]]  = None
    framework:          Optional[List[Framework]] = None
    database:           Optional[str]  = None

    # --- Checks ---
    check_secrets:      Optional[bool] = True   # TruffleHog, Gitleaks
    check_sast:         Optional[bool] = True   # Semgrep, Bandit
    check_dependencies: Optional[bool] = True   # pip-audit, npm audit
    check_iac:          Optional[bool] = False  # Checkov (Dockerfile, K8s, Terraform)
    check_git_history:  Optional[bool] = True   # secrets in old commits

    # --- LLM context ---
    sensitive_modules:  Optional[List[str]] = None  # ["auth/", "payment/"]