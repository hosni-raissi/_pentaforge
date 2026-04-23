from server.agents.intel.agent import IntelAgent


class _FakeProjectsStore:
    def list_intel_resources(self, enabled_only: bool = True):
        assert enabled_only is True
        return [
            {
                "name": "Custom Live Resource",
                "url": "https://example.com/live",
                "target_type": "linux_server",
                "content_type": "standards",
                "update_mode": "every_3_days",
            },
            {
                "name": "Shared Live Resource",
                "url": "https://example.com/shared",
                "target_type": "all",
                "content_type": "tools",
                "update_mode": "every_3_days",
            },
            {
                "name": "Static Custom Resource",
                "url": "https://example.com/static",
                "target_type": "linux_server",
                "content_type": "strategies",
                "update_mode": "static",
            },
            {
                "name": "Wrong Target Resource",
                "url": "https://example.com/web",
                "target_type": "web_app",
                "content_type": "strategies",
                "update_mode": "every_3_days",
            },
        ]


def test_collect_source_entries_uses_updateable_resources_and_preserves_metadata():
    agent = object.__new__(IntelAgent)
    agent._projects_store = _FakeProjectsStore()

    entries = agent._collect_source_entries("linux_server")
    by_name = {entry["name"]: entry for entry in entries}

    assert "PayloadsAllTheThings" in by_name
    assert "HackTricks" in by_name
    assert "Custom Live Resource" in by_name
    assert "Shared Live Resource" in by_name
    assert "Static Custom Resource" not in by_name
    assert "Wrong Target Resource" not in by_name

    custom_entry = by_name["Custom Live Resource"]
    assert custom_entry["source_kind"] == "custom"
    assert custom_entry["content_type"] == "standards"
    assert custom_entry["update_mode"] == "every_3_days"
    assert custom_entry["updatable"] is True

    builtin_entry = by_name["PayloadsAllTheThings"]
    assert builtin_entry["source_kind"] == "builtin"
    assert builtin_entry["update_mode"] == "every_3_days"
    assert builtin_entry["updatable"] is True
    assert builtin_entry["content_type"]
