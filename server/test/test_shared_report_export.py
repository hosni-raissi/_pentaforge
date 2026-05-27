from __future__ import annotations

import subprocess
from datetime import datetime, timezone
import io

from pypdf import PdfReader
from server.api.routes import share as share_routes
from server.db.projects.store import ProjectsStore


def _seed_project(store: ProjectsStore, project_id: str = "proj-1") -> None:
    store.upsert_project(
        {
            "id": project_id,
            "name": "Shared Export Project",
            "target": "https://example.com",
            "targetType": "web_app",
            "status": "idle",
            "scanProgress": 0,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "approval_mode": "custom",
            "phases": [],
            "agents": [],
            "findings": [],
            "lastScan": {},
        }
    )


def _make_store(tmp_path) -> ProjectsStore:
    store = ProjectsStore(db_path=str(tmp_path / "projects.db"))
    store.init_schema()
    _seed_project(store)
    return store


def test_shared_report_export_uses_password_protected_downloads(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    monkeypatch.setattr(share_routes, "projects_store", store)

    html_content = "<html><body><h1>Shared Report</h1><p>Protected delivery.</p></body></html>"
    store.save_report(
        "proj-1",
        report_id="report-html",
        format="html",
        content=html_content,
        metadata={"target": "https://example.com"},
    )
    share = store.create_share_link("proj-1", expires_hours=24, password="Portal123", one_time=False)

    response = share_routes.export_shared_report(
        share["token"],
        share_routes.SharedExportRequest(
            format="html",
            password="Export123",
            access_password="Portal123",
        ),
    )

    assert response.media_type == "application/zip"
    assert 'pentaforge-report-proj-1.html.zip' in response.headers["Content-Disposition"]

    archive_path = tmp_path / "shared-report.zip"
    extract_path = tmp_path / "shared-extract"
    extract_path.mkdir()
    archive_path.write_bytes(response.body)
    unzip_run = subprocess.run(
        ["7z", "x", "-pExport123", str(archive_path), f"-o{extract_path}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert unzip_run.returncode == 0, unzip_run.stderr or unzip_run.stdout
    extracted_html = extract_path / "pentaforge-report-proj-1.html"
    assert extracted_html.exists()
    assert extracted_html.read_text(encoding="utf-8") == html_content


def test_shared_pdf_export_returns_encrypted_pdf_bytes(tmp_path, monkeypatch) -> None:
    store = _make_store(tmp_path)
    monkeypatch.setattr(share_routes, "projects_store", store)

    html_content = "<html><body><h1>Shared Report</h1><p>Protected delivery.</p></body></html>"
    store.save_report(
        "proj-1",
        report_id="report-html",
        format="html",
        content=html_content,
        metadata={"target": "https://example.com"},
    )
    share = store.create_share_link("proj-1", expires_hours=24, password="Portal123", one_time=False)

    response = share_routes.export_shared_report(
        share["token"],
        share_routes.SharedExportRequest(
            format="pdf",
            password="Export123",
            access_password="Portal123",
        ),
    )

    assert response.media_type == "application/octet-stream"
    assert 'pentaforge-report-proj-1.pdf' in response.headers["Content-Disposition"]

    reader = PdfReader(io.BytesIO(response.body))
    assert reader.is_encrypted is True
    assert reader.decrypt("Export123") != 0
    assert len(reader.pages) >= 1
