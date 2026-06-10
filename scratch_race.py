import asyncio
import time

runs = {}

async def old_task_coro():
    try:
        await asyncio.sleep(10)
    except asyncio.CancelledError:
        print("old task cancelled!")
        raise
    finally:
        print("old task finally")
        runs.pop("proj", None)

async def start_scan(task):
    print("start_scan running")
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=10.0)
    except BaseException:
        print("caught base exception")
        pass
    
    runs["proj"] = "running"
    print("start_scan finished, runs =", runs)

async def main():
    runs["proj"] = "paused"
    task = asyncio.create_task(old_task_coro())
    await asyncio.sleep(0.1)
    task.cancel()
    
    await start_scan(task)
    
    await asyncio.sleep(0.1)
    print("after yield, runs =", runs)

asyncio.run(main())
