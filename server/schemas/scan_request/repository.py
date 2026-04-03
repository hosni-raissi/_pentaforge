
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class RepoInputType(str, Enum):
    github      = "github"
    gitlab      = "gitlab"
    bitbucket   = "bitbucket"
    local       = "local"       # uploaded zip


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
    language:           Optional[List[str]]  = None
    framework:          Optional[List[str]] = None
    database:           Optional[str]  = None

    description:        Optional[str]  = None