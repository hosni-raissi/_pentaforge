import httpx
import asyncio
import json

async def main():
    async with httpx.AsyncClient() as client:
        # Get the first paused project
        resp = await client.get('http://127.0.0.1:8000/api/projects')
        projects = resp.json().get('projects', [])
        paused = [p for p in projects if p.get('status') == 'paused']
        if not paused:
            print("No paused projects found. Let's use the first project.")
            if not projects:
                return
            paused = [projects[0]]
        
        project_id = paused[0]['id']
        print(f"Listening to SSE for project: {project_id}")
        
        async with client.stream('GET', f'http://127.0.0.1:8000/api/projects/{project_id}/scan/events', timeout=10.0) as response:
            count = 0
            async for line in response.aiter_lines():
                if line.startswith('data: '):
                    data = json.loads(line[6:])
                    event_name = data.get('event')
                    is_cached = data.get('is_cached', False)
                    status = data.get('data', {}).get('status')
                    print(f"Event: {event_name}, is_cached: {is_cached}, status: {status}")
                    count += 1
                    if count >= 185: # Should be 180 cache + 1 snapshot
                        break

asyncio.run(main())
