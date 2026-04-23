"""
Unit tests for granular Gmail permission parsing and scope resolution.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth.permissions import (
    get_scopes_for_permission,
    is_action_denied,
    parse_permissions_arg,
    set_permissions,
    SERVICE_PERMISSION_LEVELS,
)
from auth.scopes import (
    GMAIL_READONLY_SCOPE,
    GMAIL_LABELS_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_SETTINGS_BASIC_SCOPE,
)


class TestParsePermissionsArg:
    """Tests for parse_permissions_arg()."""

    def test_single_valid_entry(self):
        result = parse_permissions_arg(["gmail:readonly"])
        assert result == {"gmail": "readonly"}

    def test_all_services_at_readonly(self):
        entries = [f"{svc}:readonly" for svc in SERVICE_PERMISSION_LEVELS]
        result = parse_permissions_arg(entries)
        assert set(result.keys()) == set(SERVICE_PERMISSION_LEVELS.keys())

    def test_missing_colon_raises(self):
        with pytest.raises(ValueError, match="Invalid permission format"):
            parse_permissions_arg(["gmail_readonly"])

    def test_duplicate_service_raises(self):
        with pytest.raises(ValueError, match="Duplicate service"):
            parse_permissions_arg(["gmail:readonly", "gmail:full"])

    def test_unknown_service_raises(self):
        with pytest.raises(ValueError, match="Unknown service"):
            parse_permissions_arg(["fakesvc:readonly"])

    def test_unknown_level_raises(self):
        with pytest.raises(ValueError, match="Unknown level"):
            parse_permissions_arg(["gmail:superadmin"])

    def test_empty_list_returns_empty(self):
        assert parse_permissions_arg([]) == {}

    def test_extra_colon_in_value(self):
        """A level containing a colon should fail as unknown level."""
        with pytest.raises(ValueError, match="Unknown level"):
            parse_permissions_arg(["gmail:read:only"])


class TestGetScopesForPermission:
    """Tests for get_scopes_for_permission() cumulative scope expansion."""

    def test_gmail_readonly_returns_readonly_scope(self):
        scopes = get_scopes_for_permission("gmail", "readonly")
        assert GMAIL_READONLY_SCOPE in scopes

    def test_gmail_organize_includes_readonly(self):
        """Organize level should cumulatively include readonly scopes."""
        scopes = get_scopes_for_permission("gmail", "organize")
        assert GMAIL_READONLY_SCOPE in scopes
        assert GMAIL_LABELS_SCOPE in scopes
        assert GMAIL_MODIFY_SCOPE in scopes

    def test_gmail_drafts_includes_organize_and_readonly(self):
        scopes = get_scopes_for_permission("gmail", "drafts")
        assert GMAIL_READONLY_SCOPE in scopes
        assert GMAIL_LABELS_SCOPE in scopes
        assert GMAIL_COMPOSE_SCOPE in scopes

    def test_gmail_send_includes_drafts(self):
        scopes = get_scopes_for_permission("gmail", "send")
        assert GMAIL_SEND_SCOPE in scopes
        assert GMAIL_COMPOSE_SCOPE in scopes
        assert GMAIL_READONLY_SCOPE in scopes

    def test_gmail_full_includes_settings_basic(self):
        scopes = get_scopes_for_permission("gmail", "full")
        assert GMAIL_SETTINGS_BASIC_SCOPE in scopes
        assert GMAIL_SEND_SCOPE in scopes

    def test_unknown_service_raises(self):
        with pytest.raises(ValueError, match="Unknown service"):
            get_scopes_for_permission("nonexistent", "readonly")

    def test_unknown_level_raises(self):
        with pytest.raises(ValueError, match="Unknown permission level"):
            get_scopes_for_permission("gmail", "nonexistent")

    def test_no_duplicate_scopes(self):
        """Cumulative expansion should deduplicate scopes."""
        for service, levels in SERVICE_PERMISSION_LEVELS.items():
            for level_name, _ in levels:
                scopes = get_scopes_for_permission(service, level_name)
                assert len(scopes) == len(set(scopes)), (
                    f"Duplicate scopes for {service}:{level_name}"
                )


@pytest.fixture(autouse=True)
def _reset_permissions_state():
    """Ensure each test starts and ends with no active permissions."""
    set_permissions(None)
    yield
    set_permissions(None)


class TestIsActionDenied:
    """Tests for is_action_denied() and SERVICE_DENIED_ACTIONS."""

    def test_no_permissions_mode_allows_all(self):
        """Without granular permissions, no action is denied."""
        set_permissions(None)
        assert is_action_denied("gmail", "delete") is False

    def test_service_not_in_permissions_allows_all(self):
        """A service not listed in permissions should allow all actions."""
        set_permissions({"gmail": "readonly"})
        assert is_action_denied("other", "delete") is False

    def test_service_without_denied_actions_allows_all(self):
        """Gmail has no SERVICE_DENIED_ACTIONS entry, so all actions allowed."""
        set_permissions({"gmail": "readonly"})
        assert is_action_denied("gmail", "delete") is False
