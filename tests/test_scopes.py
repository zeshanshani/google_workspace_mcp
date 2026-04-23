"""
Unit tests for Gmail scope generation (Gmail-only build).
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth.scopes import (
    BASE_SCOPES,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_LABELS_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_SETTINGS_BASIC_SCOPE,
    get_scopes_for_tools,
    has_required_scopes,
    set_read_only,
)
from auth.permissions import get_scopes_for_permission, set_permissions
import auth.permissions as permissions_module


class TestGmailScopes:
    """Tests for gmail tool scope generation."""

    def setup_method(self):
        set_read_only(False)

    def teardown_method(self):
        set_read_only(False)

    def test_gmail_full_includes_all_scopes(self):
        scopes = get_scopes_for_tools(["gmail"])
        for s in (
            GMAIL_READONLY_SCOPE,
            GMAIL_SEND_SCOPE,
            GMAIL_COMPOSE_SCOPE,
            GMAIL_MODIFY_SCOPE,
            GMAIL_LABELS_SCOPE,
            GMAIL_SETTINGS_BASIC_SCOPE,
        ):
            assert s in scopes

    def test_gmail_includes_base_scopes(self):
        scopes = get_scopes_for_tools(["gmail"])
        for s in BASE_SCOPES:
            assert s in scopes

    def test_gmail_returns_unique_scopes(self):
        scopes = get_scopes_for_tools(["gmail"])
        assert len(scopes) == len(set(scopes))

    def test_gmail_readonly_mode(self):
        set_read_only(True)
        scopes = get_scopes_for_tools(["gmail"])
        assert GMAIL_READONLY_SCOPE in scopes
        assert GMAIL_SEND_SCOPE not in scopes
        assert GMAIL_MODIFY_SCOPE not in scopes


class TestHasRequiredScopes:
    """Tests for hierarchy-aware scope checking."""

    def test_exact_match(self):
        assert has_required_scopes([GMAIL_READONLY_SCOPE], [GMAIL_READONLY_SCOPE])

    def test_missing_scope_fails(self):
        assert not has_required_scopes([GMAIL_READONLY_SCOPE], [GMAIL_SEND_SCOPE])

    def test_empty_available_fails(self):
        assert not has_required_scopes([], [GMAIL_READONLY_SCOPE])

    def test_empty_required_passes(self):
        assert has_required_scopes([], [])
        assert has_required_scopes([GMAIL_READONLY_SCOPE], [])

    def test_none_available_fails(self):
        assert not has_required_scopes(None, [GMAIL_READONLY_SCOPE])

    def test_none_available_empty_required_passes(self):
        assert has_required_scopes(None, [])

    # Gmail hierarchy: gmail.modify covers readonly, send, compose, labels
    def test_gmail_modify_covers_readonly(self):
        assert has_required_scopes([GMAIL_MODIFY_SCOPE], [GMAIL_READONLY_SCOPE])

    def test_gmail_modify_covers_send(self):
        assert has_required_scopes([GMAIL_MODIFY_SCOPE], [GMAIL_SEND_SCOPE])

    def test_gmail_modify_covers_compose(self):
        assert has_required_scopes([GMAIL_MODIFY_SCOPE], [GMAIL_COMPOSE_SCOPE])

    def test_gmail_modify_covers_labels(self):
        assert has_required_scopes([GMAIL_MODIFY_SCOPE], [GMAIL_LABELS_SCOPE])

    def test_gmail_modify_does_not_cover_settings(self):
        """gmail.modify does NOT cover gmail.settings.basic."""
        assert not has_required_scopes(
            [GMAIL_MODIFY_SCOPE], [GMAIL_SETTINGS_BASIC_SCOPE]
        )

    def test_gmail_modify_covers_multiple_children(self):
        assert has_required_scopes(
            [GMAIL_MODIFY_SCOPE],
            [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE, GMAIL_LABELS_SCOPE],
        )

    def test_readonly_does_not_cover_send(self):
        assert not has_required_scopes([GMAIL_READONLY_SCOPE], [GMAIL_SEND_SCOPE])


class TestGranularPermissionsScopes:
    """Tests for granular permissions scope generation path."""

    def setup_method(self):
        set_read_only(False)
        permissions_module._PERMISSIONS = None

    def teardown_method(self):
        set_read_only(False)
        permissions_module._PERMISSIONS = None

    def test_permissions_mode_returns_base_plus_permission_scopes(self):
        set_permissions({"gmail": "send"})
        scopes = get_scopes_for_tools(["gmail"])  # enabled_tools ignored in permissions mode

        expected = set(BASE_SCOPES)
        expected.update(get_scopes_for_permission("gmail", "send"))
        assert set(scopes) == expected

    def test_permissions_mode_overrides_read_only_map(self):
        set_read_only(True)
        without_permissions = get_scopes_for_tools(["gmail"])
        assert GMAIL_READONLY_SCOPE in without_permissions
        assert GMAIL_SEND_SCOPE not in without_permissions

        set_permissions({"gmail": "send"})
        with_permissions = get_scopes_for_tools(["gmail"])
        assert GMAIL_SEND_SCOPE in with_permissions
