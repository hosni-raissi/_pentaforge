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

    credentials:        Optional[List[Credential]] = None
    description:        Optional[str]  = None