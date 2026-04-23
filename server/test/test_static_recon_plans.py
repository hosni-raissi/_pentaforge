from server.app.orchestrator import _build_static_recon_plan, _resolve_static_recon_plan
from server.constants.target_types import TARGET_TYPES
from server.db.projects import ProjectsStore


def test_static_recon_plan_persists_and_can_be_deleted(tmp_path):
    db_path = tmp_path / "projects.db"
    store = ProjectsStore(str(db_path))
    store.init_schema()

    payload = {
        "target_type": "web_app",
        "max_items": 20,
        "generated_from": "test",
        "scenarios": [
            {
                "task": "Custom recon scenario",
                "agent": "recon",
                "priority": 1,
                "details": "custom",
                "methods": ["custom"],
                "done": False,
                "status": "not yet",
            }
        ],
    }

    saved = store.upsert_static_recon_plan(target_type="web_app", payload=payload)
    loaded = store.get_static_recon_plan("web_app")
    plans = store.list_static_recon_plans()

    assert saved["target_type"] == "web_app"
    assert isinstance(loaded, dict)
    assert loaded["scenarios"][0]["task"] == "Custom recon scenario"
    assert len(plans) == 1

    deleted = store.delete_static_recon_plan("web_app")
    missing = store.get_static_recon_plan("web_app")

    assert deleted == 1
    assert missing is None


def test_build_static_recon_plan_loads_file_backed_defaults_for_all_target_types():
    for target_type in TARGET_TYPES:
        plan = _build_static_recon_plan(target_type)
        assert plan["target_type"] == target_type
        assert plan["generated_from"] == "static_data_file"
        assert isinstance(plan["scenarios"], list)
        assert len(plan["scenarios"]) > 0
        assert all(isinstance(item.get("task"), str) and item["task"].strip() for item in plan["scenarios"])


def test_resolve_static_recon_plan_replaces_legacy_default_with_file_data(tmp_path):
    db_path = tmp_path / "projects.db"
    store = ProjectsStore(str(db_path))
    store.init_schema()

    legacy_payload = {
        "target_type": "web_app",
        "max_items": 20,
        "generated_from": "built_in_target_type_template",
        "scenarios": [
            {
                "task": "Fingerprint technologies, frameworks, and exposed services from the main target",
                "agent": "recon",
                "priority": 1,
                "details": "legacy",
                "methods": ["legacy method"],
                "done": False,
                "status": "not yet",
            }
        ],
    }
    store.upsert_static_recon_plan(target_type="web_app", payload=legacy_payload)

    resolved = _resolve_static_recon_plan(store, "web_app")

    assert resolved["generated_from"] == "static_data_file"
    assert resolved["scenarios"][0]["task"] == "External Perimeter Mapping"


def test_resolve_static_recon_plan_preserves_user_saved_db_plan(tmp_path):
    db_path = tmp_path / "projects.db"
    store = ProjectsStore(str(db_path))
    store.init_schema()

    user_payload = {
        "target_type": "web_app",
        "max_items": 20,
        "generated_from": "ui_settings",
        "scenarios": [
            {
                "task": "Custom recon scenario",
                "agent": "recon",
                "priority": 1,
                "details": "custom",
                "methods": ["custom"],
                "done": False,
                "status": "not yet",
            }
        ],
    }
    store.upsert_static_recon_plan(target_type="web_app", payload=user_payload)

    resolved = _resolve_static_recon_plan(store, "web_app")

    assert resolved["generated_from"] == "ui_settings"
    assert resolved["scenarios"][0]["task"] == "Custom recon scenario"
