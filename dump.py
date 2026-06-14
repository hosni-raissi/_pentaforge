import json, sys, os
sys.path.append(os.getcwd())
from server.api.dependencies import projects_store

projects = projects_store.list_projects()
for p in projects:
    if p.get("target") == "https://www.denishe.com":
        proj = projects_store.get_project(p["id"])
        findings = proj.get("findings", [])
        for f in findings:
            print(f"Title: {f.get('title')}")
            print(f"Severity: {f.get('severity')}")
            print(f"CVSS: {f.get('cvss')}")
            print(f"Status: {f.get('status')}")
            print("---")
        break
