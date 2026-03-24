# schemas/scan_request/container.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from .credentials import Credential

class ContainerInputType(str, Enum):
    image_name  = "image_name"  # e.g. nginx:latest
    image_file  = "image_file"  # uploaded .tar image
    registry    = "registry"    # private registry URL
    compose     = "compose"     # docker-compose.yml
    kubernetes  = "kubernetes"  # K8s cluster / manifest

class ContainerRegistry(BaseModel):
    url:            str                         # e.g. registry.target.com
    username:       Optional[str]  = None
    password:       Optional[str]  = None
    token:          Optional[str]  = None

class KubernetesConfig(BaseModel):
    kubeconfig:     Optional[str]  = None       # uploaded kubeconfig file
    namespace:      Optional[str]  = None       # target namespace
    context:        Optional[str]  = None       # kube context name

class ContainerScanRequest(BaseModel):
    # --- Input ---
    input_type:         ContainerInputType
    image_name:         Optional[str]  = None   # nginx:latest
    file_path:          Optional[str]  = None   # .tar / compose / manifest
    registry:           Optional[ContainerRegistry] = None
    kubernetes:         Optional[KubernetesConfig]  = None

    # --- Checks ---
    check_image:        Optional[bool] = True   # CVEs in image layers (Trivy)
    check_config:       Optional[bool] = True   # misconfigs (privileged, root)
    check_secrets:      Optional[bool] = True   # secrets in env vars / layers
    check_network:      Optional[bool] = True   # exposed ports, network policies
    check_escape:       Optional[bool] = True   # container escape techniques
    check_rbac:         Optional[bool] = True   # K8s RBAC misconfig
    credentials:        Optional[List[Credential]] = None