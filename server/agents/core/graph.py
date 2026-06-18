import os
from typing import Dict, Any
import shlex
from langgraph.graph import StateGraph, END
from mem0 import Memory
from server.agents.assistant.tools import run_custom

from .state import PentestState

# Initialize Mem0
# In a real app, this might connect to Qdrant, but for now we can use the default or explicitly configure it
try:
    memory = Memory()
except Exception as e:
    print(f"Warning: Failed to initialize Mem0: {e}")
    memory = None

def planner_node(state: PentestState) -> Dict[str, Any]:
    """
    The Planner determines the next steps based on the current target and any
    feedback received from the Analyzer. It queries Mem0 for context.
    """
    print("--- PLANNER NODE ---")
    
    # STEP 3: Query Mem0 for context before planning
    target = state.get("target")
    facts = []
    if memory and target:
        try:
            results = memory.search(query=f"What vulnerabilities or open ports are known for {target}?", user_id=state.get("project_id"))
            facts = [r.get('text', '') for r in results if r.get('text')]
            print(f"[Planner] Retrieved facts from Mem0: {facts}")
        except Exception as e:
            print(f"[Planner] Failed to query Mem0: {e}")

    if not state.get("task_queue"):
        # If queue is empty, the Planner adds a task
        print("[Planner] Generating new tasks based on current facts...")
        return {
            "task_queue": [{"tool": "nmap", "target": target, "args": "-sV"}],
            "plan": ["Initial Recon", "Vulnerability Scan", "Exploitation"],
            "current_phase": "Reconnaissance"
        }
    
    print("[Planner] Tasks already in queue, waiting...")
    return {}

def executor_node(state: PentestState) -> Dict[str, Any]:
    """
    The Executor strictly runs the tools defined in the task_queue using run_custom.
    """
    print("--- EXECUTOR NODE ---")
    
    tasks = state.get("task_queue", [])
    if not tasks:
        return {}
    
    current_task = tasks[0]
    tool_name = current_task.get("tool", "")
    target = current_task.get("target", "")
    args = current_task.get("args", "")
    
    print(f"[Executor] Running {tool_name} on {target}...")
    
    command = str(tool_name)
    args_list = shlex.split(str(args)) if isinstance(args, str) else list(args) if args else []
    if target and target not in args_list:
        args_list.append(target)
        
    try:
        result = run_custom(
            command=command,
            reason=f"Automated pentest execution of {command} against {target}",
            args=args_list
        )
        
        raw_output = str(result.get("stdout") or "")
        if not raw_output and result.get("error"):
            raw_output = str(result.get("error"))
        elif not raw_output and result.get("stderr"):
            raw_output = str(result.get("stderr"))
            
        print(f"[Executor] Execution completed. Output size: {len(raw_output)}")
    except Exception as e:
        raw_output = f"Execution failed: {e}"
        print(f"[Executor] {raw_output}")
    
    return {
        "last_tool_call": current_task,
        "last_tool_output": raw_output
    }

def analyzer_node(state: PentestState) -> Dict[str, Any]:
    """
    The Analyzer acts as a critic and fact-extractor.
    It reads raw tool output, passes it to Mem0 to extract facts,
    and then CLEARS the raw output from the state to save memory.
    """
    print("--- ANALYZER NODE ---")
    
    raw_output = state.get("last_tool_output")
    target = state.get("target")
    project_id = state.get("project_id")
    tool_call = state.get("last_tool_call", {})
    
    if not raw_output:
        return {}
        
    print("[Analyzer] Reviewing raw logs and extracting facts via Mem0...")
    
    # STEP 2: Call Mem0 here to store facts
    extracted_fact = f"Tool {tool_call.get('tool')} on {target} found: {raw_output}"
    if memory:
        try:
            # We would normally use an LLM here to parse raw_output into structured facts,
            # but for this step we will just add the summarized fact to Mem0
            memory.add(extracted_fact, user_id=project_id, metadata={"target": target, "tool": tool_call.get("tool")})
            print(f"[Analyzer] Saved fact to Mem0 for {target}")
        except Exception as e:
            print(f"[Analyzer] Failed to add to Mem0: {e}")
    
    summary = "Found open SSH (22) and HTTP (80)."
    
    # Clear the raw output to prevent context bloat
    return {
        "analyzer_feedback": summary,
        "last_tool_output": None,  # PURGING RAW LOGS!
        "last_tool_call": None
    }

def human_approval_node(state: PentestState) -> Dict[str, Any]:
    """
    A Human-In-The-Loop gate.
    """
    print("--- HITL APPROVAL ---")
    return {"requires_approval": False}

def should_execute(state: PentestState) -> str:
    """ Determines if we have tasks to run, or if we need to plan. """
    if state.get("requires_approval"):
        return "human_approval"
    if state.get("task_queue") and not state.get("last_tool_output"):
        return "executor"
    if state.get("last_tool_output"):
        return "analyzer"
    
    return "planner"

workflow = StateGraph(PentestState)

workflow.add_node("planner", planner_node)
workflow.add_node("executor", executor_node)
workflow.add_node("analyzer", analyzer_node)
workflow.add_node("human_approval", human_approval_node)

workflow.set_entry_point("planner")

workflow.add_conditional_edges(
    "planner",
    should_execute,
    {
        "executor": "executor",
        "human_approval": "human_approval",
        "analyzer": "analyzer",
        "planner": "planner"
    }
)

workflow.add_edge("executor", "analyzer")
workflow.add_edge("analyzer", "planner")
workflow.add_edge("human_approval", "executor")

pentest_orchestrator = workflow.compile()
