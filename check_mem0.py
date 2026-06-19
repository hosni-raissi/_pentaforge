import asyncio
from server.agents.planner.agent import memory

async def main():
    if not memory:
        return
        
    print("Testing search filters...")
    results = memory.search(query="Information gathering findings", limit=10, filters={"user_id": "pentaforge_analyzer"})
    print(f"Search worked: {len(results)} results")
    for idx, r in enumerate(results):
        print(f"\n--- Result {idx + 1} ---")
        print(r.get("memory", r.get("text", str(r))))

if __name__ == "__main__":
    asyncio.run(main())
