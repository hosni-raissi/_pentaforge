from typing import TypedDict, Annotated, List, Dict, Any, Optional
import operator

# The core State for the LangGraph multi-agent loop
class PentestState(TypedDict):
    """
    This dictionary strictly defines the data that flows between the Planner, 
    Executor, and Analyzer nodes. It prevents context-window bloat by NOT
    storing endless raw tool logs in memory.
    """
    
    # 1. Scope & Target context (Static throughout the scan)
    project_id: str
    target: str          # e.g., "192.168.1.10" or "https://example.com"
    target_type: str     # e.g., "web_app", "infrastructure"
    scope_rules: Dict[str, Any] # allowed domains, forbidden IPs, etc.
    
    # 2. Dynamic Execution State
    current_phase: str   # Reconnaissance, Scanning, Exploitation, etc.
    plan: List[str]      # The high-level steps the Planner wants to execute
    
    # We use operator.add here so that when a node returns 'task_queue', 
    # it appends to the list rather than overwriting it.
    task_queue: Annotated[List[Dict[str, Any]], operator.add]
    
    # 3. Tool Feedback Loop
    # The Executor stores the raw output here temporarily. 
    # The Analyzer reads it, extracts facts, sends to Mem0, and then clears this field.
    last_tool_call: Optional[Dict[str, Any]]
    last_tool_output: Optional[str]
    
    # 4. Agent Communication
    # A place for the Analyzer to send warnings or success signals back to the Planner
    analyzer_feedback: Optional[str]
    
    # 5. Safety / HITL Check
    # If the Planner proposes a destructive tool, it pauses here.
    requires_approval: bool
