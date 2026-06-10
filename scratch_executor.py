import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

def blocking():
    print("blocking start")
    time.sleep(5)
    print("blocking end")

async def my_coro():
    loop = asyncio.get_running_loop()
    try:
        with ThreadPoolExecutor() as pool:
            await loop.run_in_executor(pool, blocking)
    finally:
        print("finally")

async def main():
    task = asyncio.create_task(my_coro())
    await asyncio.sleep(0.1)
    task.cancel()
    
    start = time.time()
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=10.0)
    except Exception as e:
        print("Caught", type(e))
    except BaseException as e:
        print("Caught BaseException", type(e))
    print(f"wait_for took {time.time() - start:.2f}s")
    print("task done?", task.done())

asyncio.run(main())
