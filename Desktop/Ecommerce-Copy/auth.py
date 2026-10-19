"""Customer accounts: username + password, or "Sign in with Google".

Wired into the Flask app by init_auth() at the bottom of app.py.
"""
import os
import re
import secrets
import time

import psycopg2
try:
    from authlib.integrations.base_client.errors import OAuthError
    from authlib.integrations.flask_client import OAuth
except ImportError:  # Authlib not installed: username/password login still works
    OAuth = None

    class OAuthError(Exception):
        pass
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

auth = Blueprint("auth", __name__)
oauth = OAuth() if OAuth else None

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
MIN_PASSWORD, MAX_PASSWORD = 8, 128  # the max stops huge inputs from being used to burn CPU on hashing

# A real hash to compare against when the username doesn't exist, so a login attempt
# takes about the same time whether or not the account exists (prevents username probing).
_DUMMY_HASH = generate_password_hash("not-a-real-password")

_run = None          # set by init_auth(): the app's database helper
_safe_next = None    # set by init_auth(): the app's safe-redirect helper
GOOGLE_ENABLED = False


# if login fails 5 times, users cannot login for 15 minutes
_FAILS = {}
MAX_FAILS, WINDOW_SECONDS = 5, 15 * 60


def _recent(key):
    now = time.time()
    hits = [t for t in _FAILS.get(key, []) if now - t < WINDOW_SECONDS]
    if hits:
        _FAILS[key] = hits
    else:
        _FAILS.pop(key, None)
    return hits


def is_throttled(key):
    return len(_recent(key)) >= MAX_FAILS


def record_failure(key):
    _recent(key)
    _FAILS.setdefault(key, []).append(time.time())


def clear_failures(key):
    _FAILS.pop(key, None)


def client_key(*parts):
    return "|".join([request.remote_addr or "?", *parts])



# Session helpers

def login_customer(row):
    """Start a fresh session for this customer. Clearing first prevents session fixation;
    the cart and the browser's own orders are carried over so nothing is lost."""
    keep = {k: session[k] for k in ("cart", "my_orders", "admin") if k in session}
    session.clear()
    session.update(keep)
    session["customer_id"] = row["customer_id"]
    session["customer_name"] = row["username"]
    session["_csrf"] = secrets.token_urlsafe(32)  # new token for the new login state


CUSTOMER_SESSION_KEYS = ("customer_id", "customer_name", "cart", "my_orders", "oauth_next")


def logout_customer():
    """Remove everything that belongs to the customer. The admin flag is left alone,
    so logging out as a customer never logs out an admin in the same browser."""
    for k in CUSTOMER_SESSION_KEYS:
        session.pop(k, None)
    session["_csrf"] = secrets.token_urlsafe(32)


def _after_login_url():
    return _safe_next(request.args.get("next") or request.form.get("next"), url_for("store"))



# Username / password

@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("customer_id"):
        return redirect(url_for("store"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        error = None
        if not USERNAME_RE.match(username):
            error = "Username must be 3-30 characters: letters, numbers, dot, dash or underscore."
        elif not (MIN_PASSWORD <= len(password) <= MAX_PASSWORD):
            error = f"Password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters long."
        elif password != confirm:
            error = "The two passwords don't match."
        if error:
            flash(error, "error")
        else:
            try:
                rows = _run(
                    "INSERT INTO customers (username, password_hash) VALUES (%s, %s) "
                    "RETURNING customer_id, username",
                    (username, generate_password_hash(password)), fetch=True)
            except psycopg2.errors.UniqueViolation:
                flash("That username is already taken. Please choose another.", "error")
            except psycopg2.Error:
                flash("Could not create your account right now. Please try again.", "error")
            else:
                login_customer(rows[0])
                flash(f"Welcome, {rows[0]['username']}! Your account has been created.", "ok")
                return redirect(_after_login_url())
    return render_template("customer_signup.html",
                           next=request.args.get("next", ""))


@auth.route("/login", methods=["GET", "POST"])
def login():
    if session.get("customer_id"):
        return redirect(url_for("store"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")[:MAX_PASSWORD]
        key = client_key(username.lower())
        if is_throttled(key):
            flash("Too many failed attempts. Please wait 15 minutes and try again.", "error")
            return render_template("customer_login.html",
                                   next=request.args.get("next", "")), 429
        rows = _run("SELECT customer_id, username, password_hash FROM customers "
                    "WHERE LOWER(username) = LOWER(%s)", (username,), fetch=True)
        row = rows[0] if rows else None
        stored = (row or {}).get("password_hash") or _DUMMY_HASH  # Google-only accounts have no password
        ok = check_password_hash(stored, password) and row is not None and row["password_hash"]
        if ok:
            clear_failures(key)
            login_customer(row)
            flash(f"Welcome back, {row['username']}!", "ok")
            return redirect(_after_login_url())
        record_failure(key)
        flash("Incorrect username or password.", "error")  # same message either way
    return render_template("customer_login.html",
                           next=request.args.get("next", ""))


@auth.route("/logout", methods=["POST"])  # POST + CSRF token, so another site can't log you out
def logout():
    logout_customer()
    flash("You have been logged out.", "ok")
    return redirect(url_for("auth.login"))



# Sign in with Google (OpenID Connect)

def _unique_username(base):
    base = re.sub(r"[^A-Za-z0-9_.-]", "", base)[:22] or "user"
    if len(base) < 3:
        base += "user"
    candidate = base
    for _ in range(20):
        if not _run("SELECT 1 FROM customers WHERE LOWER(username) = LOWER(%s)", (candidate,), fetch=True):
            return candidate
        candidate = f"{base}{secrets.randbelow(10000):04d}"
    return f"{base}{secrets.token_hex(3)}"


@auth.route("/google/login")
def google_login():
    if not GOOGLE_ENABLED:
        flash("Google sign-in isn't available right now. Please use a username and password.", "error")
        return redirect(url_for("auth.login"))
    session["oauth_next"] = _safe_next(request.args.get("next"), url_for("store"))
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI") or url_for("auth.google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth.route("/google/callback")
def google_callback():
    if not GOOGLE_ENABLED:
        return redirect(url_for("auth.login"))
    target = _safe_next(session.pop("oauth_next", None), url_for("store"))
    try:
        token = oauth.google.authorize_access_token()  # checks state, nonce and the ID-token signature
    except OAuthError as e:
        current_app.logger.warning("Google sign-in failed: %s", e)
        if session.get("customer_id"):
            # A repeated callback (double click, browser retry) arrives after the first one already
            # signed this person in. The code and state were used up, so it errors - ignore it quietly.
            return redirect(target)
        flash("Google sign-in was cancelled or failed. Please try again.", "error")
        return redirect(url_for("auth.login"))
    info = token.get("userinfo") or {}
    sub = info.get("sub")
    if not sub or not info.get("email_verified"):
        flash("Your Google account's email address must be verified to sign in.", "error")
        return redirect(url_for("auth.login"))

    try:
        rows = _run("SELECT customer_id, username FROM customers WHERE google_sub = %s", (sub,), fetch=True)
        if not rows:
            email = (info.get("email") or "")[:150]
            base = (info.get("given_name") or info.get("name") or email.split("@")[0] or "user")
            rows = _run(
                "INSERT INTO customers (username, email, google_sub) VALUES (%s, %s, %s) "
                "RETURNING customer_id, username",
                (_unique_username(base), email, sub), fetch=True)
    except psycopg2.Error:
        flash("Could not sign you in right now. Please try again.", "error")
        return redirect(url_for("auth.login"))

    login_customer(rows[0])
    flash(f"Welcome, {rows[0]['username']}!", "ok")
    return redirect(target)



def init_auth(app, run, safe_next):
    global _run, _safe_next, GOOGLE_ENABLED
    _run, _safe_next = run, safe_next

    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
    GOOGLE_ENABLED = bool(client_id and client_secret and oauth is not None)
    if client_id and client_secret and oauth is None:
        app.logger.warning("GOOGLE_CLIENT_ID is set but Authlib is not installed: pip install Authlib")
    if not GOOGLE_ENABLED:
        app.logger.warning("Google sign-in is not configured: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env")
    if GOOGLE_ENABLED:
        app.config["GOOGLE_CLIENT_ID"] = client_id
        app.config["GOOGLE_CLIENT_SECRET"] = client_secret
        oauth.init_app(app)
        oauth.register(
            name="google",
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    @app.context_processor
    def inject_customer():
        return {"customer_name": session.get("customer_name")}

    app.register_blueprint(auth, url_prefix="/account")