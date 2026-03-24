# schemas/scan_request/prompt.py
from pydantic import BaseModel
from typing import Optional

class PromptScanRequest(BaseModel):
    project_id:     str                      # link to existing project
    prompt:         str                      # the instruction to the LLM
    context:        Optional[str]  = None    # extra context if needed