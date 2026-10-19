import hmac
import os
import secrets
import uuid
from datetime import datetime
from urllib.parse import urlparse

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import Blueprint, Flask, flash, jsonify, redirect, render_template, request, session, url_for, abort, g
from markupsafe import Markup

from auth import init_auth, is_throttled, record_failure, clear_failures, client_key

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))  # reads credentials from the .env file next to app.py

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key or app.secret_key == "secretkey911":
    raise RuntimeError("Set a long random SECRET_KEY in the .env file "
                       "(python -c \"import secrets; print(secrets.token_hex(32))\").")

# Images may be at most 400 KB. save_image() enforces that per file; this outer cap only
# stops huge request bodies early (400 KB + room for the other form fields).
MAX_IMAGE_BYTES = 400 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES + 64 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",  # set COOKIE_SECURE=1 when served over HTTPS
)
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "ecommerce-db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
}

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
os.makedirs(UPLOAD_DIR, exist_ok=True)


def run(sql, params=(), fetch=False):
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn, conn.cursor() as cur:  # commits on success, rolls back on error
            cur.execute(sql, params)
            return cur.fetchall() if fetch else None
    finally:
        conn.close()


_extras_ready = False


def ensure_extras():
    """Create what reviews and 'my orders' need, the first time they are used:
    orders.customer_id (which account placed the order) and the product_reviews table."""
    global _extras_ready
    if _extras_ready:
        return
    run("""ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_id INT
               REFERENCES customers(customer_id) ON DELETE SET NULL""")
    run("""CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id)""")
    run("""CREATE TABLE IF NOT EXISTS product_reviews (
               review_id   SERIAL PRIMARY KEY,
               product_key VARCHAR(100) NOT NULL,   -- the product page id: product_code, or sku if none
               customer_id INT REFERENCES customers(customer_id) ON DELETE SET NULL,
               author      VARCHAR(30)  NOT NULL,
               rating      SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
               body        TEXT NOT NULL DEFAULT '',
               created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
               updated_at  TIMESTAMP NOT NULL DEFAULT NOW(),
               UNIQUE (product_key, customer_id)    -- one review per customer per product (editable)
           )""")
    run("""CREATE TABLE IF NOT EXISTS cart_items (
               customer_id INT NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
               sku         VARCHAR(100) NOT NULL,
               qty         INT NOT NULL CHECK (qty > 0),
               PRIMARY KEY (customer_id, sku)
           )""")
    _extras_ready = True


#  Saved carts 
# The session cart stays the working copy. For a logged-in customer it is stored in cart_items
# (keyed by customer_id) whenever it changes, and restored the next time that customer logs in.

def _save_cart(customer_id, cart):
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn, conn.cursor() as cur:
            cur.execute("DELETE FROM cart_items WHERE customer_id = %s", (customer_id,))
            if cart:
                cur.executemany("INSERT INTO cart_items (customer_id, sku, qty) VALUES (%s, %s, %s)",
                                [(customer_id, sku, int(q)) for sku, q in cart.items() if int(q) > 0])
    finally:
        conn.close()


@app.before_request
def restore_saved_cart():
    g.cart_before = None
    cid = session.get("customer_id")
    if not cid or request.endpoint == "static":
        return
    g.cart_before = dict(session.get("cart", {}))
    if session.get("_cart_loaded") == cid:
        return
    try:  # first request after logging in: merge the saved cart into this session
        ensure_extras()
        merged = dict(session.get("cart", {}))
        for r in run("SELECT sku, qty FROM cart_items WHERE customer_id = %s", (cid,), fetch=True):
            merged[r["sku"]] = merged.get(r["sku"], 0) + r["qty"]
        session["cart"] = merged  # quantities are trimmed to real stock when the cart is shown
        session["_cart_loaded"] = cid
    except psycopg2.Error:
        app.logger.exception("Could not restore the saved cart")


@app.after_request
def persist_cart(resp):
    cid = session.get("customer_id")
    before = getattr(g, "cart_before", None)
    if cid and before is not None and dict(session.get("cart", {})) != before:
        try:
            _save_cart(cid, session.get("cart", {}))
        except psycopg2.Error:
            app.logger.exception("Could not save the cart")
    return resp


def _looks_like(ext, head):
    """Check the file's first bytes really match its extension (a renamed .exe/.html is rejected)."""
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext == "gif":
        return head[:6] in (b"GIF87a", b"GIF89a")
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    return False


def save_image(file):
    """Save an uploaded image under a random name. Returns the filename or None.
    Raises ValueError if the file is too big (over 400 KB), the wrong type, or not a real image."""
    if not file or not file.filename:
        return None
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_EXT:
        raise ValueError("Image must be a PNG, JPG, GIF or WEBP file.")
    stream = file.stream
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    if size == 0:
        raise ValueError("The image file is empty.")
    if size > MAX_IMAGE_BYTES:
        raise ValueError(f"Image is too large ({size / 1024:.0f} KB). The limit is 400 KB.")
    if not _looks_like(ext, stream.read(12)):
        raise ValueError("That file is not a valid image.")
    stream.seek(0)
    name = f"{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOAD_DIR, name))
    return name


def friendly(e):
    """Show validation problems to the user, but never raw database errors (they leak table names etc.)."""
    if isinstance(e, (ValueError, KeyError)):
        return str(e)
    app.logger.error("Database error: %s", e)
    return "a database error occurred. Please try again."


def discard_image(name):
    if name:
        try:
            os.remove(os.path.join(UPLOAD_DIR, name))
        except OSError:
            pass


def clean_code(value):
    """Product codes are stored upper-case so 'ts-100' and 'TS-100' match."""
    return (value or "").strip().upper() or None


def product_codes():
    rows = run("SELECT DISTINCT product_code FROM items WHERE product_code IS NOT NULL ORDER BY 1", fetch=True)
    return [r["product_code"] for r in rows]


ITEMS_SQL = """
    SELECT i.sku, i.name, i.qty, i.rate, i.amount, i.closing_stock, i.color, i.size,
           i.image_filename, i.product_code,
           g.group_name, c.category_name, t.type_name, b.brand_name
    FROM items i
    JOIN brand_setup b    ON b.brand_id = i.brand_id
    JOIN type_setup t     ON t.type_id = b.type_id
    JOIN category_setup c ON c.category_id = t.category_id
    JOIN group_setup g    ON g.group_id = c.group_id
    ORDER BY i.created_at DESC
"""

# One item plus the ids of its whole hierarchy chain (used by the edit page)
ITEM_ONE_SQL = """
    SELECT i.*, b.type_id, t.category_id, c.group_id
    FROM items i
    JOIN brand_setup b    ON b.brand_id = i.brand_id
    JOIN type_setup t     ON t.type_id = b.type_id
    JOIN category_setup c ON c.category_id = t.category_id
    WHERE i.sku = %s
"""

# level -> (table, id column, name column, parent column)
LEVELS = {
    "group": ("group_setup", "group_id", "group_name", None),
    "category": ("category_setup", "category_id", "category_name", "group_id"),
    "type": ("type_setup", "type_id", "type_name", "category_id"),
    "brand": ("brand_setup", "brand_id", "brand_name", "type_id"),
}
# what sits directly below each level (used in the "can't delete" message)
CHILDREN = {"group": "categories", "category": "types", "type": "brands", "brand": "items"}


@app.errorhandler(413)
def too_large(_):
    flash("That upload is too large. Images must be 400 KB or smaller.", "error")
    return redirect(url_for("index"))


#  Items 

@app.route("/items")
def index():
    return render_template(
        "index.html",
        items=run(ITEMS_SQL, fetch=True),
        groups=run("SELECT group_id AS id, group_name AS name FROM group_setup ORDER BY 2", fetch=True),
        codes=product_codes(),
    )


@app.route("/items", methods=["POST"])
def add_item():
    f = request.form
    saved = None
    try:
        qty = int(f["qty"])
        rate = float(f["rate"])
        closing = int(f["closing_stock"]) if f.get("closing_stock") else qty
        saved = save_image(request.files.get("image"))
        run(
            """INSERT INTO items (sku, name, qty, rate, closing_stock, color, size, brand_id,
                                  image_filename, product_code)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (f["sku"].strip(), f["name"].strip(), qty, rate, closing,
             f.get("color", "").strip(), f.get("size", "").strip(), int(f["brand_id"]),
             saved, clean_code(f.get("product_code"))),
        )
        flash(f"Item {f['sku']} added.", "ok")
    except psycopg2.errors.UniqueViolation:
        discard_image(saved)
        flash(f"SKU {f['sku']} already exists. Use a different SKU.", "error")
    except (ValueError, KeyError, psycopg2.Error) as e:
        discard_image(saved)
        flash(f"Could not add item: {friendly(e)}", "error")
    return redirect(url_for("index"))


@app.route("/items/<sku>/edit")
def edit_item(sku):
    rows = run(ITEM_ONE_SQL, (sku,), fetch=True)
    if not rows:
        flash(f"Item {sku} not found.", "error")
        return redirect(url_for("index"))
    item = rows[0]
    return render_template(
        "edit.html",
        item=item,
        groups=run("SELECT group_id AS id, group_name AS name FROM group_setup ORDER BY 2", fetch=True),
        categories=run("SELECT category_id AS id, category_name AS name FROM category_setup "
                       "WHERE group_id = %s ORDER BY 2", (item["group_id"],), fetch=True),
        types=run("SELECT type_id AS id, type_name AS name FROM type_setup "
                  "WHERE category_id = %s ORDER BY 2", (item["category_id"],), fetch=True),
        brands=run("SELECT brand_id AS id, brand_name AS name FROM brand_setup "
                   "WHERE type_id = %s ORDER BY 2", (item["type_id"],), fetch=True),
        codes=product_codes(),
    )


@app.route("/items/<sku>/edit", methods=["POST"])
def update_item(sku):
    f = request.form
    old = run("SELECT image_filename FROM items WHERE sku = %s", (sku,), fetch=True)
    if not old:
        flash(f"Item {sku} not found.", "error")
        return redirect(url_for("index"))
    old_image = old[0]["image_filename"]
    saved = None
    try:
        qty = int(f["qty"])
        rate = float(f["rate"])
        closing = int(f["closing_stock"])
        saved = save_image(request.files.get("image"))
        if saved:
            new_image = saved
        elif f.get("remove_image") == "1":
            new_image = None
        else:
            new_image = old_image
        run(
            """UPDATE items SET name = %s, qty = %s, rate = %s, closing_stock = %s, color = %s,
                                size = %s, product_code = %s, brand_id = %s, image_filename = %s
               WHERE sku = %s""",
            (f["name"].strip(), qty, rate, closing, f.get("color", "").strip(),
             f.get("size", "").strip(), clean_code(f.get("product_code")),
             int(f["brand_id"]), new_image, sku),
        )
        if new_image != old_image:
            discard_image(old_image)
        flash(f"Item {sku} updated.", "ok")
        return redirect(url_for("index"))
    except (ValueError, KeyError, psycopg2.Error) as e:
        discard_image(saved)
        flash(f"Could not update item: {friendly(e)}", "error")
        return redirect(url_for("edit_item", sku=sku))


@app.route("/items/<sku>/delete", methods=["POST"])
def delete_item(sku):
    try:
        rows = run("DELETE FROM items WHERE sku = %s RETURNING image_filename", (sku,), fetch=True)
        if rows:
            discard_image(rows[0]["image_filename"])
            flash(f"Item {sku} deleted.", "ok")
        else:
            flash(f"Item {sku} not found.", "error")
    except psycopg2.Error as e:
        flash(f"Could not delete item: {friendly(e)}", "error")
    return redirect(url_for("index"))


@app.route("/api/<level>")
def options(level):
    """Options for the cascading dropdowns: /api/category?parent=<group_id> etc."""
    if level not in LEVELS or level == "group":
        return jsonify([]), 404
    table, id_col, name_col, parent_col = LEVELS[level]
    rows = run(
        f"SELECT {id_col} AS id, {name_col} AS name FROM {table} WHERE {parent_col} = %s ORDER BY 2",
        (request.args.get("parent", type=int),), fetch=True,
    )
    return jsonify(rows)


#  Store (landing page) 

def build_cards(rows):
    groups = {}

    for r in rows:
        key = r["product_code"] or r["sku"]
        groups.setdefault(key, []).append(r)

    cards = []

    for card_id, rows_ in groups.items():
        variants = []

        for r in rows_:
            variants.append({
                "sku": r["sku"],
                "name": r["name"],
                "brand": r["brand_name"],
                "rate": float(r["rate"] or 0),
                "stock": float(r["closing_stock"] or 0),
                "color": r["color"],
                "size": r["size"],
                "image": url_for("static", filename="uploads/" + r["image_filename"]) if r["image_filename"] else None,
                "label": " / ".join(x for x in [r["color"], r["size"]] if x) or r["sku"]
            })

        default = 0

        cards.append({
            "id": card_id,
            "variants": variants,
            "default": default
        })

    return cards


@app.route("/")
def store():
    # "Our Collection": public page, only the items from the store's items table
    rows = run(ITEMS_SQL, fetch=True)
    groups = sorted({r["group_name"] for r in rows})
    q = request.args.get("q", "").strip()
    group = request.args.get("group", "")
    if group:
        rows = [r for r in rows if r["group_name"] == group]
    if q:
        keys = ("name", "sku", "product_code", "color", "size", "brand_name",
                "type_name", "category_name", "group_name")
        rows = [r for r in rows if q.lower() in " ".join(str(r[k] or "") for k in keys).lower()]
    return render_template("store.html", cards=build_cards(rows), groups=groups, q=q, group=group)

@app.route("/product/<path:card_id>")
def product(card_id):
    all_cards = build_cards(run(ITEMS_SQL, fetch=True))
    card = next((c for c in all_cards if c["id"] == card_id), None)
    if card is None:
        abort(404)
    related = [c for c in all_cards if c is not card][:4]
    ensure_extras()
    revs = run("""SELECT r.rating, r.body, r.author, r.created_at, r.customer_id,
                         EXISTS (SELECT 1 FROM orders o
                                 JOIN order_items oi ON oi.order_id = o.order_id
                                 JOIN items i ON i.sku = oi.sku
                                 WHERE o.customer_id = r.customer_id AND o.status <> 'cancelled'
                                   AND COALESCE(i.product_code, i.sku) = r.product_key) AS verified
                  FROM product_reviews r WHERE r.product_key = %s ORDER BY r.created_at DESC""",
               (card_id,), fetch=True)
    card["reviews"] = [{"author": r["author"], "rating": r["rating"], "text": r["body"],
                        "verified": r["verified"], "date": r["created_at"].strftime("%d %b %Y")} for r in revs]
    card["rating"] = round(sum(r["rating"] for r in revs) / len(revs), 1) if revs else 0
    me = session.get("customer_id")
    card["my_review"] = next(({"rating": r["rating"], "text": r["body"]} for r in revs
                              if me and r["customer_id"] == me), None)
    avgs = {a["product_key"]: float(a["avg"]) for a in run(
        """SELECT product_key, AVG(rating) AS avg FROM product_reviews
           WHERE product_key = ANY(%s) GROUP BY product_key""", ([c["id"] for c in related],), fetch=True)}
    for c in related:
        c["rating"] = round(avgs.get(c["id"], 0), 1)
    return render_template("product.html", card=card, related=related)


#  Hierarchy setup 

@app.route("/setup")
def setup():
    return render_template(
        "setup.html",
        groups=run("SELECT * FROM group_setup ORDER BY group_name", fetch=True),
        categories=run("""SELECT c.*, g.group_name FROM category_setup c
                          JOIN group_setup g USING (group_id) ORDER BY g.group_name, c.category_name""", fetch=True),
        types=run("""SELECT t.type_id, t.type_name, g.group_name || ' > ' || c.category_name AS path, t.category_id
                     FROM type_setup t JOIN category_setup c USING (category_id)
                     JOIN group_setup g USING (group_id) ORDER BY 3, 2""", fetch=True),
        brands=run("""SELECT b.brand_id, b.brand_name,
                             g.group_name || ' > ' || c.category_name || ' > ' || t.type_name AS path,
                             b.type_id
                      FROM brand_setup b JOIN type_setup t USING (type_id)
                      JOIN category_setup c USING (category_id)
                      JOIN group_setup g USING (group_id) ORDER BY 3, 2""", fetch=True),
    )


@app.route("/setup/<level>", methods=["POST"])
def add_setup(level):
    if level not in LEVELS:
        return "Unknown level", 404
    table, _, name_col, parent_col = LEVELS[level]
    name = request.form["name"].strip()
    try:
        if parent_col:
            run(f"INSERT INTO {table} ({name_col}, {parent_col}) VALUES (%s, %s)",
                (name, int(request.form["parent_id"])))
        else:
            run(f"INSERT INTO {table} ({name_col}) VALUES (%s)", (name,))
        flash(f"Added {level} '{name}'.", "ok")
    except psycopg2.errors.UniqueViolation:
        flash(f"The {level} '{name}' already exists there.", "error")
    except (ValueError, KeyError, psycopg2.Error) as e:
        flash(f"Could not add {level}: {friendly(e)}", "error")
    return redirect(url_for("setup"))


@app.route("/setup/<level>/<int:row_id>/rename", methods=["POST"])
def rename_setup(level, row_id):
    if level not in LEVELS:
        return "Unknown level", 404
    table, id_col, name_col, _ = LEVELS[level]
    name = request.form.get("name", "").strip()
    if not name:
        flash("Name can't be empty.", "error")
        return redirect(url_for("setup"))
    try:
        run(f"UPDATE {table} SET {name_col} = %s WHERE {id_col} = %s", (name, row_id))
        flash(f"Saved {level} name '{name}'.", "ok")
    except psycopg2.errors.UniqueViolation:
        flash(f"The {level} '{name}' already exists there.", "error")
    except psycopg2.Error as e:
        flash(f"Could not rename {level}: {friendly(e)}", "error")
    return redirect(url_for("setup"))


@app.route("/setup/<level>/<int:row_id>/delete", methods=["POST"])
def delete_setup(level, row_id):
    if level not in LEVELS:
        return "Unknown level", 404
    table, id_col, _, _ = LEVELS[level]
    try:
        run(f"DELETE FROM {table} WHERE {id_col} = %s", (row_id,))
        flash(f"Deleted {level}.", "ok")
    except psycopg2.errors.ForeignKeyViolation:
        flash(f"Can't delete this {level}: it still has {CHILDREN[level]} under it. "
              f"Delete or move those first.", "error")
    except psycopg2.Error as e:
        flash(f"Could not delete {level}: {friendly(e)}", "error")
    return redirect(url_for("setup"))



# Admin login: keeps the management pages away from shop customers


ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")


def safe_next(target, default):
    """Only allow redirects to paths on this site."""
    if (target and target.startswith("/") and not target.startswith("//")
            and "\\" not in target and "\r" not in target and "\n" not in target):
        return target
    return default


#  CSRF protection: every POST must carry the secret token embedded in our forms
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["csrf_input"] = lambda: Markup(
    f'<input type="hidden" name="csrf_token" value="{csrf_token()}">')


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(sent.encode(), session.get("_csrf", "").encode()):
            abort(400, description="csrf")


@app.errorhandler(400)
def bad_request(e):
    if getattr(e, "description", "") == "csrf":
        flash("Your session expired or the form was invalid. Please try again.", "error")
        ref = urlparse(request.referrer or "")
        back = ref.path + ("?" + ref.query if ref.query else "") if ref.netloc == request.host else ""
        return redirect(safe_next(back, url_for("store")))
    return "Bad request", 400


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


#  Who may see what 
# Visitors who are not logged in may ONLY see these pages (plus the login/signup pages).
# To make another page public (e.g. contact), add its endpoint name here.
PUBLIC_ENDPOINTS = {
    "static", "shop.browse", "store", "admin_login", "site.about", "site.info", "site.contact",
    "auth.login", "auth.signup", "auth.logout", "auth.google_login", "auth.google_callback",
}
# Pages that need a customer login (an admin may also see them): everything else in the
# shop (cart, checkout, orders) plus the home page, product pages and the info pages.
CUSTOMER_ENDPOINTS = {"product"}
# Anything not listed above (items, orders, hierarchy setup, the dropdown API...) is admin only.


@app.before_request
def require_login():
    ep = request.endpoint
    if ep is None or ep in PUBLIC_ENDPOINTS:  # unknown URLs fall through to the normal 404/405
        return None
    # After logging in, send the person back to the page they asked for (GET requests only).
    back = request.full_path.rstrip("?") if request.method == "GET" else None

    if ep in CUSTOMER_ENDPOINTS or request.blueprint == "shop":
        if session.get("customer_id") or session.get("admin"):
            return None
        flash("Please log in or sign up to view this page.", "error")
        return redirect(url_for("auth.login", next=back or url_for("shop.browse")))

    if not session.get("admin"):  # admin-only area
        flash("Please log in as admin to open that page.", "error")
        return redirect(url_for("admin_login", next=back or url_for("index")))
    return None


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        given = request.form.get("password", "")[:256].encode()
        key = client_key("admin")
        if is_throttled(key):
            flash("Too many failed attempts. Please wait 15 minutes and try again.", "error")
            return render_template("login.html"), 429
        if not ADMIN_PASSWORD:
            flash("ADMIN_PASSWORD is not set in the .env file, so login is disabled.", "error")
        elif hmac.compare_digest(given, ADMIN_PASSWORD.encode()):
            clear_failures(key)
            keep = {k: session[k] for k in ("cart", "my_orders", "customer_id", "customer_name") if k in session}
            session.clear()  # new session on privilege change (prevents session fixation)
            session.update(keep)
            session["admin"] = True
            return redirect(safe_next(request.args.get("next"), url_for("index")))
        else:
            record_failure(key)
            flash("Wrong password.", "error")
    return render_template("login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin", None)
    if not session.get("customer_id"):
        # Nobody else is logged in on this browser, so drop any leftover cart/orders
        session.pop("cart", None)
        session.pop("my_orders", None)
    session["_csrf"] = secrets.token_urlsafe(32)
    return redirect(url_for("admin_login"))



# Admin: orders placed through the shop


# status -> status it may move to. Cancelling puts the stock back.
ORDER_FLOW = {
    "pending": ["shipped", "delivered", "cancelled"],
    "shipped": ["delivered", "cancelled"],
    "delivered": [],
    "cancelled": [],
}


@app.route("/orders")
def orders():
    rows = run("SELECT * FROM orders ORDER BY created_at DESC", fetch=True)
    return render_template("orders.html", orders=rows)


@app.route("/orders/<int:order_id>")
def order_detail(order_id):
    rows = run("SELECT * FROM orders WHERE order_id = %s", (order_id,), fetch=True)
    if not rows:
        flash(f"Order #{order_id} not found.", "error")
        return redirect(url_for("orders"))
    lines = run("SELECT * FROM order_items WHERE order_id = %s ORDER BY order_item_id", (order_id,), fetch=True)
    return render_template("order_detail.html", order=rows[0], lines=lines,
                           next_statuses=ORDER_FLOW[rows[0]["status"]])


@app.route("/orders/<int:order_id>/status", methods=["POST"])
def update_order_status(order_id):
    new = request.form.get("status", "")
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn, conn.cursor() as cur:  # one transaction: status and stock change together
            cur.execute("SELECT status FROM orders WHERE order_id = %s FOR UPDATE", (order_id,))
            row = cur.fetchone()
            if not row:
                flash(f"Order #{order_id} not found.", "error")
            elif new not in ORDER_FLOW[row["status"]]:
                flash("That status change isn't allowed.", "error")
            else:
                if new == "cancelled":
                    cur.execute(
                        """UPDATE items i SET closing_stock = i.closing_stock + oi.qty
                           FROM order_items oi WHERE oi.order_id = %s AND oi.sku = i.sku""",
                        (order_id,))
                cur.execute("UPDATE orders SET status = %s WHERE order_id = %s", (new, order_id))
                flash(f"Order #{order_id} marked {new}."
                      + (" Stock was returned to the items." if new == "cancelled" else ""), "ok")
    except psycopg2.Error as e:
        flash(f"Could not update order: {friendly(e)}", "error")
    finally:
        conn.close()
    return redirect(url_for("order_detail", order_id=order_id))



# Customer shop: browse, cart, checkout. Lives under /shop and uses the
# same database, so stock changes show up in the admin pages instantly.


shop = Blueprint("shop", __name__, url_prefix="/shop")


class OutOfStock(Exception):
    pass


@app.context_processor
def inject_cart_count():
    # Only logged-in people (customer or admin) can use the cart, so show 0 for everyone else
    if not (session.get("customer_id") or session.get("admin")):
        return {"cart_count": 0}
    return {"cart_count": sum(session.get("cart", {}).values())}


# Store details shown in the header, footer and on the About / More info / Contact pages.
STORE = {
    "name": os.getenv("STORE_NAME", "Kindred"),
    "tagline": os.getenv("STORE_TAGLINE", "Quality goods for everyday life, with stock levels you can trust."),
    "email": os.getenv("STORE_EMAIL", "kindred@gmail.com"),
    "phone": os.getenv("STORE_PHONE", "+977 0000000000"),
    "address": os.getenv("STORE_ADDRESS", "Old Town Road, Kathmandu, Nepal"),
    "hours": os.getenv("STORE_HOURS", "Sun\u2013Fri, 10:00\u201318:00"),
}
ADMIN_PAGES = {"index", "edit_item", "orders", "order_detail", "setup", "messages"}


@app.context_processor
def inject_site():
    return {
        "store": STORE,
        "now_year": datetime.now().year,
        # admin dashboard pages get the compact admin layout; everything else uses the storefront layout
        "admin_view": bool(session.get("admin")) and request.endpoint in ADMIN_PAGES,
    }


def load_cart():
    """Cart lines with live prices and stock. Quantities are trimmed if stock has dropped.
    Returns (lines, total, changed)."""
    cart = dict(session.get("cart", {}))
    if not cart:
        return [], 0, False
    rows = run(
        """SELECT i.sku, i.name, i.color, i.size, i.rate, i.closing_stock, i.image_filename, b.brand_name
           FROM items i JOIN brand_setup b ON b.brand_id = i.brand_id
           WHERE i.sku = ANY(%s)""", (list(cart),), fetch=True)
    by_sku = {r["sku"]: r for r in rows}
    lines, new_cart, changed = [], {}, False
    for sku, qty in cart.items():
        r = by_sku.get(sku)
        if not r or r["closing_stock"] < 1:
            changed = True  # item deleted or sold out
            continue
        if qty > r["closing_stock"]:
            qty, changed = r["closing_stock"], True
        new_cart[sku] = qty
        lines.append({
            "sku": sku, "name": r["name"], "brand": r["brand_name"],
            "variant": " / ".join(x for x in (r["color"], r["size"]) if x),
            "rate": r["rate"], "qty": qty, "available": r["closing_stock"],
            "line_total": r["rate"] * qty,
            "image": url_for("static", filename="uploads/" + r["image_filename"]) if r["image_filename"] else None,
        })
    if changed:
        session["cart"] = new_cart
    return lines, sum(l["line_total"] for l in lines), changed


def place_order(info, lines, customer_id=None):
    """Reduce stock and record the order in ONE transaction.
    The guarded UPDATE means two customers can never buy the last unit."""
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn, conn.cursor() as cur:  # rolls back everything if anything fails
            bought = []
            for l in sorted(lines, key=lambda x: x["sku"]):
                cur.execute(
                    """UPDATE items SET closing_stock = closing_stock - %s
                       WHERE sku = %s AND closing_stock >= %s
                       RETURNING sku, name, color, size, rate""",
                    (l["qty"], l["sku"], l["qty"]))
                row = cur.fetchone()
                if row is None:
                    raise OutOfStock(l["name"])
                bought.append((row, l["qty"]))
            total = sum(r["rate"] * q for r, q in bought)
            cur.execute(
                """INSERT INTO orders (customer_name, email, phone, address, total, customer_id)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING order_id""",
                (info["name"], info["email"], info["phone"], info["address"], total, customer_id))
            order_id = cur.fetchone()["order_id"]
            for r, q in bought:
                cur.execute(
                    """INSERT INTO order_items (order_id, sku, item_name, color, size, qty, rate)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (order_id, r["sku"], r["name"], r["color"], r["size"], q, r["rate"]))
            return order_id
    finally:
        conn.close()


@shop.route("/")
def browse():
    # Home page: introduction only; not the items
    return render_template("shop_browse.html", cards=build_cards(run(ITEMS_SQL, fetch=True)))

@shop.route("/cart")
def cart():
    lines, total, changed = load_cart()
    if changed:
        flash("Your cart was adjusted to match current stock.", "error")
    return render_template("shop_cart.html", lines=lines, total=total)


@shop.route("/cart/add", methods=["POST"])
def cart_add():
    back = safe_next(request.form.get("back"), url_for("shop.browse"))
    sku = request.form.get("sku", "")
    try:
        qty = max(1, int(request.form.get("qty", 1)))
    except ValueError:
        qty = 1
    rows = run("SELECT name, closing_stock FROM items WHERE sku = %s", (sku,), fetch=True)
    if not rows:
        flash("That item is no longer available.", "error")
        return redirect(back)
    item = rows[0]
    cart_ = dict(session.get("cart", {}))
    have = cart_.get(sku, 0)
    room = item["closing_stock"] - have
    if room <= 0:
        flash(f"No more {item['name']} available. You already have all {item['closing_stock']} in your cart."
              if have else f"{item['name']} is out of stock.", "error")
    else:
        add = min(qty, room)
        cart_[sku] = have + add
        session["cart"] = cart_
        note = f" Only {item['closing_stock']} in stock." if add < qty else ""
        flash(f"Added {add} x {item['name']} to your cart.{note}", "ok")
    return redirect(back)


@shop.route("/cart/update", methods=["POST"])
def cart_update():
    sku = request.form.get("sku", "")
    cart_ = dict(session.get("cart", {}))
    if sku in cart_:
        try:
            qty = int(request.form.get("qty", "0"))
        except ValueError:
            qty = cart_[sku]
        if qty <= 0:
            del cart_[sku]
        else:
            cart_[sku] = qty  # trimmed to real stock the next time the cart loads
        session["cart"] = cart_
    return redirect(url_for("shop.cart"))


@shop.route("/cart/remove", methods=["POST"])
def cart_remove():
    cart_ = dict(session.get("cart", {}))
    cart_.pop(request.form.get("sku", ""), None)
    session["cart"] = cart_
    return redirect(url_for("shop.cart"))


@shop.route("/checkout", methods=["GET", "POST"])
def checkout():
    lines, total, changed = load_cart()
    if not lines:
        flash("Your cart is empty.", "error")
        return redirect(url_for("shop.cart"))
    if changed:
        flash("Your cart changed because stock was updated. Please review it and try again.", "error")
        return redirect(url_for("shop.cart"))
    if request.method == "POST":
        info = {k: request.form.get(k, "").strip() for k in ("name", "email", "phone", "address")}
        if not all(info.values()):
            flash("Please fill in all the delivery details.", "error")
        else:
            try:
                ensure_extras()
                order_id = place_order(info, lines, session.get("customer_id"))
            except OutOfStock as e:
                flash(f"Sorry, {e} just sold out or has less stock than you asked for. "
                      f"Nothing was charged or reserved. Please review your cart.", "error")
                return redirect(url_for("shop.cart"))
            except psycopg2.Error as e:
                flash(f"Could not place your order: {friendly(e)}", "error")
            else:
                session.pop("cart", None)
                session["my_orders"] = session.get("my_orders", []) + [order_id]
                return redirect(url_for("shop.thanks", order_id=order_id))
    form = request.form if request.method == "POST" else {"name": session.get("customer_name", "")}
    return render_template("shop_checkout.html", lines=lines, total=total, form=form)


@shop.route("/order/<int:order_id>")
def thanks(order_id):
    # Customers have no accounts, so only the browser that placed the order may view it
    rows = run("SELECT * FROM orders WHERE order_id = %s", (order_id,), fetch=True) \
        if order_id in session.get("my_orders", []) else []
    if not rows:
        flash("Order not found.", "error")
        return redirect(url_for("shop.browse"))
    lines = run("SELECT * FROM order_items WHERE order_id = %s ORDER BY order_item_id", (order_id,), fetch=True)
    return render_template("shop_thanks.html", order=rows[0], lines=lines)


#  Reviews and "my orders" 

@shop.route("/review", methods=["POST"])
def add_review():
    key = request.form.get("card_id", "").strip()[:100]
    back = url_for("product", card_id=key) if key else url_for("shop.browse")
    cid = session.get("customer_id")
    if not cid:
        flash("Please log in with a customer account to review products.", "error")
        return redirect(back)
    try:
        rating = int(request.form.get("rating", ""))
    except ValueError:
        rating = 0
    body = request.form.get("body", "").strip()[:1000]
    if not 1 <= rating <= 5:
        flash("Please choose a star rating from 1 to 5.", "error")
        return redirect(back)
    try:
        ensure_extras()
        if not run("SELECT 1 FROM items WHERE COALESCE(product_code, sku) = %s LIMIT 1", (key,), fetch=True):
            abort(404)
        run("""INSERT INTO product_reviews (product_key, customer_id, author, rating, body)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (product_key, customer_id)
               DO UPDATE SET rating = EXCLUDED.rating, body = EXCLUDED.body, updated_at = NOW()""",
            (key, cid, session.get("customer_name", "Customer"), rating, body))
        flash("Thanks! Your review has been saved.", "ok")
    except psycopg2.Error as e:
        flash(f"Could not save your review: {friendly(e)}", "error")
    return redirect(back)


ORDER_FILTERS = ("pending", "shipped", "delivered", "cancelled")


@shop.route("/my-orders")
def my_orders():
    cid = session.get("customer_id")
    if not cid:  # e.g. the admin browsing the shop: orders are tied to customer accounts
        flash("Order history is available when you are logged in with a customer account.", "error")
        return redirect(url_for("shop.browse"))
    ensure_extras()
    status = request.args.get("status", "")
    rows = run("SELECT * FROM orders WHERE customer_id = %s ORDER BY created_at DESC", (cid,), fetch=True)
    counts = {s: sum(1 for o in rows if o["status"] == s) for s in ORDER_FILTERS}
    if status in ORDER_FILTERS:
        rows = [o for o in rows if o["status"] == status]
    lines = {}
    if rows:
        for l in run("SELECT * FROM order_items WHERE order_id = ANY(%s) ORDER BY order_item_id",
                     ([o["order_id"] for o in rows],), fetch=True):
            lines.setdefault(l["order_id"], []).append(l)
    return render_template("my_orders.html", orders=rows, lines=lines, status=status,
                           counts=counts, filters=ORDER_FILTERS)


@shop.route("/my-orders/<int:order_id>/cancel", methods=["POST"])
def cancel_my_order(order_id):
    cid = session.get("customer_id")
    if not cid:
        return redirect(url_for("auth.login", next=url_for("shop.my_orders")))
    ensure_extras()
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn, conn.cursor() as cur:  # one transaction: status and stock change together
            cur.execute("SELECT status FROM orders WHERE order_id = %s AND customer_id = %s FOR UPDATE",
                        (order_id, cid))
            row = cur.fetchone()
            if not row:
                flash("Order not found.", "error")
            elif row["status"] != "pending":
                flash(f"Order #{order_id} is already {row['status']}, so it can no longer be cancelled here. "
                      "Please contact us if you need help.", "error")
            else:
                cur.execute(
                    """UPDATE items i SET closing_stock = i.closing_stock + oi.qty
                       FROM order_items oi WHERE oi.order_id = %s AND oi.sku = i.sku""", (order_id,))
                cur.execute("UPDATE orders SET status = 'cancelled' WHERE order_id = %s", (order_id,))
                flash(f"Order #{order_id} has been cancelled.", "ok")
    except psycopg2.Error as e:
        flash(f"Could not cancel the order: {friendly(e)}", "error")
    finally:
        conn.close()
    return redirect(url_for("shop.my_orders"))


app.register_blueprint(shop)


# Public information pages shown in the navbar
site = Blueprint("site", __name__)


@site.route("/about")
def about():
    return render_template("about.html")


@site.route("/info")
def info():
    return render_template("info.html")


CONTACT_TOPICS = ["Order support", "Product question", "Press & partnerships", "Something else"]
_contact_table_ready = False


def ensure_contact_table():
    """Create the contact_messages table on first use, so existing databases need no manual migration."""
    global _contact_table_ready
    if not _contact_table_ready:
        run("""CREATE TABLE IF NOT EXISTS contact_messages (
                   message_id SERIAL PRIMARY KEY,
                   first_name VARCHAR(80)  NOT NULL,
                   last_name  VARCHAR(80)  NOT NULL,
                   email      VARCHAR(150) NOT NULL,
                   topic      VARCHAR(60)  NOT NULL,
                   message    TEXT NOT NULL,
                   created_at TIMESTAMP NOT NULL DEFAULT NOW()
               )""")
        _contact_table_ready = True


@site.route("/contact", methods=["GET", "POST"])
def contact():
    form = {"first_name": "", "last_name": "", "email": "", "topic": CONTACT_TOPICS[0], "message": ""}
    if request.method == "POST":
        if request.form.get("website"):  # hidden honeypot field: only bots fill it in
            return render_template("contact.html", form=form, topics=CONTACT_TOPICS, sent=True)
        for key in ("first_name", "last_name", "email", "message"):
            form[key] = request.form.get(key, "").strip()
        form["first_name"], form["last_name"] = form["first_name"][:80], form["last_name"][:80]
        form["email"], form["message"] = form["email"][:150], form["message"][:3000]
        topic = request.form.get("topic", "")
        form["topic"] = topic if topic in CONTACT_TOPICS else CONTACT_TOPICS[-1]

        if not all(form[k] for k in ("first_name", "last_name", "email", "message")):
            flash("Please fill in every field.", "error")
        elif "@" not in form["email"] or "." not in form["email"].rsplit("@", 1)[-1]:
            flash("Please enter a valid email address.", "error")
        else:
            try:
                ensure_contact_table()
                run("""INSERT INTO contact_messages (first_name, last_name, email, topic, message)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (form["first_name"], form["last_name"], form["email"], form["topic"], form["message"]))
                return render_template("contact.html", form=form, topics=CONTACT_TOPICS, sent=True)
            except psycopg2.Error:
                app.logger.exception("Could not save contact message")
                flash("Sorry, we couldn't send your message just now. Please try again in a moment.", "error")
    return render_template("contact.html", form=form, topics=CONTACT_TOPICS, sent=False)


@app.route("/messages")  # admin only: any endpoint not listed in the public/customer sets is admin only
def messages():
    ensure_contact_table()
    rows = run("SELECT * FROM contact_messages ORDER BY created_at DESC LIMIT 200", fetch=True)
    return render_template("messages.html", rows=rows)


app.register_blueprint(site)
init_auth(app, run, safe_next)  # customer login / signup / logout / Google sign-in


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")