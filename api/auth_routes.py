"""
auth_routes.py — Login / logout endpoints.

Three routes:
  GET  /login        Serve the login page HTML
  POST /auth/login   Process the form, set session cookie, redirect
  GET  /auth/logout  Clear the session cookie, redirect to login

Why POST for login?
  GET requests are logged in server logs, browser history, and proxy
  caches. Credentials would be visible in query params. POST keeps
  them in the request body which is not logged or cached.

Why redirect (303) after POST?
  The "Post/Redirect/Get" pattern. After a successful or failed POST,
  we redirect to a GET so that if the user hits browser back/refresh
  they don't resubmit the form.

Cookie settings:
  httponly=True  — JS cannot read the token (XSS protection)
  samesite=strict — Cookie not sent on cross-site requests (CSRF protection)
  secure=False   — We're HTTP-only locally; set True if you add HTTPS
"""

import os

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, RedirectResponse

from app.auth import (
    check_credentials,
    check_login_rate_limit,
    create_session,
    reset_login_attempts,
    revoke_session,
    COOKIE_NAME,
    SESSION_DURATION_S,
)

router = APIRouter()


@router.get("/login")
def login_page():
    """Serve the self-contained login page."""
    return FileResponse("static/login.html")


@router.post("/auth/login")
async def do_login(request: Request):
    """
    Read username + password from the form body.
    On success: create session, set HttpOnly cookie, redirect to dashboard.
    On failure: redirect back to /login with ?error=invalid.
    Throttled to 5 attempts/minute per source IP — too many returns
    ?error=throttled and skips bcrypt entirely.
    """
    client_ip = request.client.host if request.client else ""
    if not check_login_rate_limit(client_ip):
        return RedirectResponse("/login?error=throttled", status_code=303)

    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    # check_credentials handles timing-safe comparison internally
    if not check_credentials(username, password):
        # Check if the app is not configured yet (different error message)
        if not os.getenv("APP_PASSWORD_HASH"):
            return RedirectResponse("/login?error=not_configured", status_code=303)
        return RedirectResponse("/login?error=invalid", status_code=303)

    reset_login_attempts(client_ip)
    token    = create_session()
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        key      = COOKIE_NAME,
        value    = token,
        httponly = True,            # not readable by JS
        max_age  = SESSION_DURATION_S,
        samesite = "strict",        # CSRF protection
        secure   = False,           # set True if you add HTTPS
    )
    return response


@router.get("/auth/logout")
def do_logout(request: Request):
    """Revoke the current session and redirect to the login page."""
    token = request.cookies.get(COOKIE_NAME)
    if token:
        revoke_session(token)

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response
