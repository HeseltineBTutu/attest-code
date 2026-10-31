"""Synthetic administrative demo API for AUTH-ADMIN-001.

Controlled educational fixture, not production authentication. Credentials
are synthetic constants; there are no real secrets or identity services.
Each factory returns a fresh application object; tests never mutate a
shared global app.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Sequence

from fastapi import Depends, FastAPI, HTTPException, Request

ADMIN_TOKEN = "synthetic-admin-token"
USER_TOKEN = "synthetic-user-token"
ADMIN_PREFIX = "/admin"


def _principal(authorization: str | None) -> str | None:
    """Return 'admin', 'user', or None for unknown/missing credentials."""
    if authorization is None:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    if token == ADMIN_TOKEN:
        return "admin"
    if token == USER_TOKEN:
        return "user"
    return None


def _require_admin(request: Request) -> None:
    """Guard: 401 without credentials, 403 without the administrator role."""
    principal = _principal(request.headers.get("authorization"))
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if principal != "admin":
        raise HTTPException(status_code=403, detail="administrator role required")


def _health() -> dict[str, str]:
    return {"status": "ok"}


def _admin_users() -> dict[str, object]:
    return {"users": ["synthetic-user-1", "synthetic-user-2"]}


def _admin_settings() -> dict[str, object]:
    return {"settings": {"mode": "synthetic"}}


def _extra_admin() -> dict[str, bool]:
    return {"extra": True}


def _hanging_users() -> dict[str, object]:
    time.sleep(3600)
    return {"users": []}


CRASH_MARKER = "CRASH-FIXTURE-ABOUT-TO-EXIT"
"""Stderr marker proving the crashing endpoint ran before it dies.

Written with an unbuffered fd-level write: ``os._exit`` skips
stdio flushing, so only ``os.write`` survives to the parent's
capture. The parent asserts this marker to distinguish the
intended crash from a silent early exit.
"""


def _crashing_users() -> dict[str, object]:
    os.write(2, CRASH_MARKER.encode("ascii") + b"\n")
    os._exit(1)
    return {"users": []}


def admin_route_paths(app: FastAPI) -> tuple[str, ...]:
    """Inventory registered administrative routes by path prefix.

    Limitation: purely prefix-based. Mounted sub-applications, dynamic
    routes, and admin behavior under non-/admin paths are not discovered.
    """
    paths: set[str] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        if isinstance(path, str) and path.startswith(ADMIN_PREFIX):
            paths.add(path)
    return tuple(sorted(paths))


def _build_app(
    *,
    protect_users: bool,
    protect_settings: bool,
    extra_admin_paths: Sequence[str] = (),
    users_endpoint: Callable[[], dict[str, object]] = _admin_users,
    settings_endpoint: Callable[[], dict[str, object]] = _admin_settings,
) -> FastAPI:
    app = FastAPI(title="Attest Code demo API")
    app.add_api_route("/health", _health, methods=["GET"])
    users_deps = [Depends(_require_admin)] if protect_users else []
    settings_deps = [Depends(_require_admin)] if protect_settings else []
    app.add_api_route("/admin/users", users_endpoint, methods=["GET"], dependencies=users_deps)
    app.add_api_route(
        "/admin/settings", settings_endpoint, methods=["GET"], dependencies=settings_deps
    )
    for extra in extra_admin_paths:
        app.add_api_route(extra, _extra_admin, methods=["GET"])
    return app


def create_vulnerable_app() -> FastAPI:
    """Both admin endpoints exposed without authentication."""
    return _build_app(protect_users=False, protect_settings=False)


def create_incomplete_repair_app() -> FastAPI:
    """Only /admin/users secured; /admin/settings still exposed."""
    return _build_app(protect_users=True, protect_settings=False)


def create_repaired_app() -> FastAPI:
    """All admin endpoints require the administrator role."""
    return _build_app(protect_users=True, protect_settings=True)


def create_app_with_extra_admin_route(extra: str = "/admin/audit") -> FastAPI:
    """Repaired app plus an additional undeclared admin endpoint."""
    return _build_app(protect_users=True, protect_settings=True, extra_admin_paths=(extra,))


def create_hanging_app() -> FastAPI:
    """Fault-demonstration fixture: /admin/users never responds."""
    return _build_app(protect_users=True, protect_settings=True, users_endpoint=_hanging_users)


def create_crashing_app() -> FastAPI:
    """Fault-demonstration fixture: /admin/users kills its own process."""
    return _build_app(protect_users=True, protect_settings=True, users_endpoint=_crashing_users)
