"""Demo API fixtures behave as specified over plain HTTP."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.demo_api import (
    ADMIN_TOKEN,
    USER_TOKEN,
    admin_route_paths,
    create_app_with_extra_admin_route,
    create_crashing_app,
    create_hanging_app,
    create_incomplete_repair_app,
    create_repaired_app,
    create_vulnerable_app,
)


def _status(app: FastAPI, path: str, token: str | None) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return int(TestClient(app).get(path, headers=headers).status_code)


def test_vulnerable_app_exposes_both_endpoints() -> None:
    app = create_vulnerable_app()
    for path in ("/admin/users", "/admin/settings"):
        assert _status(app, path, None) == 200
        assert _status(app, path, USER_TOKEN) == 200
        assert _status(app, path, ADMIN_TOKEN) == 200


def test_incomplete_repair_leaves_settings_exposed() -> None:
    app = create_incomplete_repair_app()
    assert _status(app, "/admin/users", None) == 401
    assert _status(app, "/admin/users", USER_TOKEN) == 403
    assert _status(app, "/admin/users", ADMIN_TOKEN) == 200
    assert _status(app, "/admin/settings", None) == 200


def test_repaired_app_enforces_roles_on_both_endpoints() -> None:
    app = create_repaired_app()
    for path in ("/admin/users", "/admin/settings"):
        assert _status(app, path, None) == 401
        assert _status(app, path, USER_TOKEN) == 403
        assert _status(app, path, ADMIN_TOKEN) == 200


def test_unknown_token_is_unauthenticated() -> None:
    app = create_repaired_app()
    assert _status(app, "/admin/users", "bogus-token") == 401


def test_inventory_lists_admin_routes_only() -> None:
    assert admin_route_paths(create_repaired_app()) == ("/admin/settings", "/admin/users")


def test_inventory_includes_undeclared_extra_route() -> None:
    assert "/admin/audit" in admin_route_paths(create_app_with_extra_admin_route())


def test_fault_fixtures_share_admin_inventory() -> None:
    expected = ("/admin/settings", "/admin/users")
    assert admin_route_paths(create_hanging_app()) == expected
    assert admin_route_paths(create_crashing_app()) == expected


def test_factories_return_distinct_objects() -> None:
    assert create_vulnerable_app() is not create_vulnerable_app()
    assert create_repaired_app() is not create_incomplete_repair_app()
