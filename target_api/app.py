"""Intentionally VULNERABLE demo API -- for local testing of the detector only.

Safe by design: it uses an in-memory database and a fake file system, so a
"successful" attack never touches anything real. Still, only run it bound to
127.0.0.1 and never deploy it.

Run:  uvicorn target_api.app:app --host 127.0.0.1 --port 8000

Planted vulnerabilities (each one is marked VULNERABLE in the code):
  POST /login            SQL injection + no rate limit (brute force)
  GET  /products/search  SQL injection
  GET  /orders/{id}      BOLA / IDOR (no ownership check)
  PUT  /users/me         mass assignment (client can set "role")
  POST /comments         stored XSS (text saved unsanitized)
  GET  /files            path traversal (against a fake file system)
"""
import posixpath
import random
import secrets
import sqlite3
import threading

from fastapi import Body, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from common import seed as S

app = FastAPI(title="Vulnerable Demo API (do not deploy)")

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row
_lock = threading.Lock()
TOKENS: dict[str, int] = {}          # token -> user id

FAKE_FS = {
    "/app/public/readme.txt": "Welcome to the demo shop API.",
    "/app/public/terms.txt": "Terms of service: be nice.",
    "/app/public/logo.txt": "[ASCII LOGO]",
    "/app/config/secrets.env": "DB_PASSWORD=not-a-real-secret",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash  (fake demo data)",
}


def _query(sql: str, params: tuple = ()) -> list[dict]:
    with _lock:
        cur = _db.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        _db.commit()
        return rows


def _seed() -> None:
    rng = random.Random(1)
    _db.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                           email TEXT, name TEXT, role TEXT);
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER,
                            qty INTEGER, address TEXT);
        CREATE TABLE comments(id INTEGER PRIMARY KEY, user_id INTEGER, text TEXT);
        """
    )
    _db.execute("INSERT INTO users VALUES (1, ?, ?, 'admin@example.com', 'Admin', 'admin')",
                (S.ADMIN_USERNAME, S.ADMIN_PASSWORD))
    for i in range(1, S.N_USERS + 1):
        _db.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, 'user')",
                    (S.user_id(i), S.username(i), S.password(i),
                     f"user{i}@example.com", f"User {i}"))
    for word in S.PRODUCT_WORDS:
        for color in S.COLORS:
            _db.execute("INSERT INTO products(name, price, description) VALUES (?, ?, ?)",
                        (f"{word} {color}", round(rng.uniform(5, 900), 2), f"A nice {color} {word}."))
    for uid in range(1, S.N_USERS + 2):
        for _ in range(S.ORDERS_PER_USER):
            _db.execute("INSERT INTO orders(user_id, product_id, qty, address) VALUES (?, ?, ?, ?)",
                        (uid, rng.randint(1, S.n_products()), rng.randint(1, 3), f"{uid} Demo Street"))
    _db.commit()


_seed()


@app.exception_handler(sqlite3.Error)
async def sql_error_handler(request, exc):
    # Verbose error leak -- typical of vulnerable apps and a useful detection signal.
    return JSONResponse(status_code=500, content={"error": f"database error: {exc}"})


def current_user(authorization: str | None = Header(default=None)) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing token")
    uid = TOKENS.get(authorization[7:])
    if uid is None:
        raise HTTPException(401, "invalid token")
    return uid


class LoginBody(BaseModel):
    username: str
    password: str


class CommentBody(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginBody):
    # VULNERABLE: SQL injection (string concatenation) and no rate limiting.
    rows = _query(
        f"SELECT id, username, role FROM users "
        f"WHERE username='{body.username}' AND password='{body.password}'"
    )
    if not rows:
        raise HTTPException(401, "invalid credentials")
    token = secrets.token_hex(8)
    TOKENS[token] = rows[0]["id"]
    return {"token": token, "user": rows[0]["username"]}


@app.get("/products/search")
def search_products(q: str = ""):
    # VULNERABLE: SQL injection (string concatenation).
    rows = _query(f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'")
    return {"query": q, "count": len(rows), "results": rows}


@app.get("/products/{product_id}")
def get_product(product_id: int):
    rows = _query("SELECT * FROM products WHERE id=?", (product_id,))
    if not rows:
        raise HTTPException(404, "product not found")
    return rows[0]


@app.get("/orders")
def list_orders(uid: int = Depends(current_user)):
    return _query("SELECT id, product_id, qty FROM orders WHERE user_id=?", (uid,))


@app.get("/orders/{order_id}")
def get_order(order_id: int, uid: int = Depends(current_user)):
    # VULNERABLE (BOLA/IDOR): never checks that the order belongs to `uid`.
    rows = _query("SELECT * FROM orders WHERE id=?", (order_id,))
    if not rows:
        raise HTTPException(404, "order not found")
    return rows[0]


@app.get("/users/me")
def me(uid: int = Depends(current_user)):
    return _query("SELECT id, username, email, name, role FROM users WHERE id=?", (uid,))[0]


@app.put("/users/me")
def update_me(body: dict = Body(...), uid: int = Depends(current_user)):
    # VULNERABLE (mass assignment): "role" should never be client-editable.
    for key, value in body.items():
        if key in {"email", "name", "role"}:
            _query(f"UPDATE users SET {key}=? WHERE id=?", (str(value), uid))
    return me(uid)


@app.post("/comments")
def add_comment(body: CommentBody, uid: int = Depends(current_user)):
    # VULNERABLE (stored XSS): text is stored and later served without sanitizing.
    _query("INSERT INTO comments(user_id, text) VALUES (?, ?)", (uid, body.text))
    return {"status": "created"}


@app.get("/comments")
def list_comments():
    return _query("SELECT id, user_id, text FROM comments ORDER BY id DESC LIMIT 20")


@app.get("/files")
def get_file(name: str):
    # VULNERABLE (path traversal): `name` is joined to the base dir without checks,
    # so "../../etc/passwd" or "/etc/passwd" escapes /app/public. (Fake file system.)
    path = posixpath.normpath(posixpath.join("/app/public", name))
    if path not in FAKE_FS:
        raise HTTPException(404, "file not found")
    return {"path": path, "content": FAKE_FS[path]}
