import asyncio
import time
from langgraph.graph import StateGraph, START, END

def my_node(state):
    print("my_node start")
    time.sleep(5)
    print("my_node end")
    return {"counter": state.get("counter", 0) + 1}

async def run_graph():
    builder = StateGraph(dict)
    builder.add_node("my_node", my_node)
    builder.add_edge(START, "my_node")
    builder.add_edge("my_node", END)
    graph = builder.compile()
    
    try:
        await graph.ainvoke({"counter": 0})
    except asyncio.CancelledError:
        print("graph cancelled!")
        raise
    finally:
        print("graph finally")

async def main():
    task = asyncio.create_task(run_graph())
    await asyncio.sleep(0.5)
    task.cancel()
    
    start = time.time()
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=10.0)
    except BaseException as e:
        print("Caught BaseException:", type(e))
    
    print(f"wait_for took {time.time() - start:.2f}s")

asyncio.run(main())
