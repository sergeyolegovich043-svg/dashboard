from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import mimetypes
import os
import re
import secrets
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = Path(os.environ.get("DASHBOARD_DB", BASE_DIR / "monitor.db"))

SESSION_COOKIE = "site_dashboard_session"
SESSION_TTL_HOURS = int(os.environ.get("SESSION_TTL_HOURS", "12"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "600"))
HTTP_TIMEOUT_SECONDS = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "10"))
SSL_TIMEOUT_SECONDS = float(os.environ.get("SSL_TIMEOUT_SECONDS", "8"))
MAX_WORKERS = int(os.environ.get("CHECK_WORKERS", "8"))
SSL_WARNING_DAYS = 14
DOMAIN_WARNING_DAYS = 14

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

INITIAL_SITE_URLS = [
    "https://fasadvizor.ru/",
    "https://stroykamera.ru/",
    "https://anketa.gk-osnova.ru/",
    "https://beliykrest.ru/",
    "https://eco.osnova.group/",
    "https://book.osnova.group/",
    "http://bitru.team/",
    "https://up-art.ru/",
    "https://wevo.ru/",
    "https://terra360.ru/",
    "https://welcome.osnova.group/",
    "https://start.osnova.group/",
    "https://osnova.group/career/vacancy",
    "http://greatestate.tilda.ws/",
    "evobiotics.ru",
    "https://goodini.app/",
    "gtechcoin.tilda.ws",
    "https://smbase.pro/",
    "https://osnova.group/",
    "https://m-fin.pro/",
    "https://gk-osnova.ru/",
    "https://o-master.ru/",
    "https://red-7.ru/",
    "https://nametkin-tower.ru/",
    "https://nametkin-tower.moscow/",
    "https://mirapolis.city/",
    "https://very-botsad.ru/",
    "https://zm-residence.ru/",
    "https://fizteh.city/",
    "https://emotion-zk.ru/",
    "https://zk-mainstreet.ru/",
    "https://uno.moscow/",
    "https://gogolpark.ru/",
    "http://bitru.pro/",
    "https://wevolife.ru/",
    "https://trade-estate.ru/",
    "https://termoland.ru/",
    "https://phystechpark.ru/",
    "https://e-tag.pro/",
    "https://www.erino.ru/",
    "https://hotel-lepota.ru/",
    "https://remont-360.ru/",
    "https://kedo.gk-osnova.ru/login",
    "http://rental.phystechpark.tilda.ws/",
    "https://health-card.io/",
    "https://lk.gk-osnova.ru/auth",
    "https://erinomedcentr.ru/",
    "https://sport.erino.ru",
    "https://goodzone.ru",
    "https://torgrows.ru",
    "https://tdy.ru",
    "https://arenda.torgrows.ru",
    "https://dok3.ru/",
    "https://zk-sensation.ru/",
    "https://troitskoe-osnova.ru/",
]

CHECK_LOCK = threading.Lock()
CHECK_RUNNING = False


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return to_iso(utc_now())


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=bytes.fromhex(salt),
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(expected)),
        ).hex()
        return secrets.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def normalize_url(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("URL обязателен")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = f"https://{cleaned}"

    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Поддерживаются только HTTP и HTTPS")
    if not parsed.netloc:
        raise ValueError("Некорректный URL")

    path = parsed.path or "/"
    return urllib.parse.urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            "",
            parsed.query,
            "",
        )
    )


def make_site_name(url: str) -> str:
    parsed = urllib.parse.urlparse(normalize_url(url))
    host = parsed.netloc.removeprefix("www.")
    path = parsed.path.strip("/")
    return host if not path else f"{host}/{path}"


def days_until_date(value: str | None) -> int | None:
    if not value:
        return None
    try:
        expires = date.fromisoformat(value)
    except ValueError:
        return None
    return (expires - utc_now().date()).days


def validate_domain_date(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("Дата окончания должна быть строкой")
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ValueError("Дата окончания должна быть в формате YYYY-MM-DD") from exc


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                availability_status TEXT NOT NULL DEFAULT 'unknown',
                http_status INTEGER,
                response_time_ms INTEGER,
                last_checked_at TEXT,
                last_error TEXT,
                ssl_status TEXT NOT NULL DEFAULT 'unknown',
                ssl_expires_at TEXT,
                ssl_days_remaining INTEGER,
                domain_expires_at TEXT,
                domain_days_remaining INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        now = iso_now()
        admin_exists = conn.execute("SELECT 1 FROM users WHERE username = ?", ("admin",)).fetchone()
        if not admin_exists:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
                ("admin", hash_password("qwerty455"), now, now),
            )

        site_count = conn.execute("SELECT COUNT(*) AS count FROM sites").fetchone()["count"]
        if site_count == 0:
            for raw_url in INITIAL_SITE_URLS:
                url = normalize_url(raw_url)
                conn.execute(
                    """
                    INSERT INTO sites (
                        name, url, domain_days_remaining, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (make_site_name(url), url, None, now, now),
                )
        conn.commit()


def cleanup_expired_sessions() -> None:
    with get_db() as conn:
        rows = conn.execute("SELECT token_hash, expires_at FROM sessions").fetchall()
        expired_hashes = [row["token_hash"] for row in rows if parse_iso(row["expires_at"]) <= utc_now()]
        if expired_hashes:
            conn.executemany("DELETE FROM sessions WHERE token_hash = ?", [(token,) for token in expired_hashes])
            conn.commit()


def create_session(user_id: int) -> tuple[str, str, datetime]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    csrf_token = secrets.token_urlsafe(32)
    expires_at = utc_now() + timedelta(hours=SESSION_TTL_HOURS)
    now = iso_now()
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_hash, user_id, csrf_token, to_iso(expires_at), now, now),
        )
        conn.commit()
    return token, csrf_token, expires_at


def delete_session(token: str) -> None:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()


def get_session(token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, u.username
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if not row:
            return None
        if parse_iso(row["expires_at"]) <= utc_now():
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            conn.commit()
            return None
        conn.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (iso_now(), token_hash))
        conn.commit()
        return row


def site_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    domain_days = days_until_date(row["domain_expires_at"])
    if domain_days != row["domain_days_remaining"]:
        with get_db() as conn:
            conn.execute(
                "UPDATE sites SET domain_days_remaining = ?, updated_at = ? WHERE id = ?",
                (domain_days, iso_now(), row["id"]),
            )
            conn.commit()
    return {
        "id": row["id"],
        "name": row["name"],
        "url": row["url"],
        "availability_status": row["availability_status"],
        "http_status": row["http_status"],
        "response_time_ms": row["response_time_ms"],
        "last_checked_at": row["last_checked_at"],
        "last_error": row["last_error"],
        "ssl_status": row["ssl_status"],
        "ssl_expires_at": row["ssl_expires_at"],
        "ssl_days_remaining": row["ssl_days_remaining"],
        "domain_expires_at": row["domain_expires_at"],
        "domain_days_remaining": domain_days,
    }


def list_sites() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sites ORDER BY name COLLATE NOCASE ASC, id ASC").fetchall()
    return [site_row_to_dict(row) for row in rows]


def get_site(site_id: int) -> sqlite3.Row | None:
    with get_db() as conn:
        return conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()


def create_site(payload: dict[str, Any]) -> dict[str, Any]:
    url = normalize_url(str(payload.get("url", "")))
    name = str(payload.get("name") or make_site_name(url)).strip()
    if not name:
        name = make_site_name(url)
    if len(name) > 160:
        raise ValueError("Название не должно быть длиннее 160 символов")
    domain_expires_at = validate_domain_date(payload.get("domain_expires_at"))
    now = iso_now()
    with get_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO sites (
                name, url, domain_expires_at, domain_days_remaining, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, url, domain_expires_at, days_until_date(domain_expires_at), now, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (cur.lastrowid,)).fetchone()
    return site_row_to_dict(row)


def update_site(site_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
    existing = get_site(site_id)
    if not existing:
        return None
    url = normalize_url(str(payload.get("url", existing["url"])))
    name = str(payload.get("name") or make_site_name(url)).strip()
    if not name:
        name = make_site_name(url)
    if len(name) > 160:
        raise ValueError("Название не должно быть длиннее 160 символов")
    domain_expires_at = validate_domain_date(payload.get("domain_expires_at"))
    with get_db() as conn:
        conn.execute(
            """
            UPDATE sites
            SET name = ?, url = ?, domain_expires_at = ?, domain_days_remaining = ?, updated_at = ?
            WHERE id = ?
            """,
            (name, url, domain_expires_at, days_until_date(domain_expires_at), iso_now(), site_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return site_row_to_dict(row)


def delete_site_record(site_id: int) -> bool:
    with get_db() as conn:
        cur = conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))
        conn.commit()
    return cur.rowcount > 0


def check_http(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SiteAvailabilityDashboard/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = int(response.getcode())
            response.read(1)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "availability_status": "available" if 200 <= status <= 399 else "unavailable",
            "http_status": status,
            "response_time_ms": elapsed_ms,
            "last_error": None,
        }
    except urllib.error.HTTPError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "availability_status": "available" if 200 <= exc.code <= 399 else "unavailable",
            "http_status": int(exc.code),
            "response_time_ms": elapsed_ms,
            "last_error": f"HTTP {exc.code}",
        }
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "availability_status": "unavailable",
            "http_status": None,
            "response_time_ms": elapsed_ms,
            "last_error": str(exc)[:300],
        }


def check_ssl(url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return {"ssl_status": "missing", "ssl_expires_at": None, "ssl_days_remaining": None}

    hostname = parsed.hostname
    if not hostname:
        return {"ssl_status": "missing", "ssl_expires_at": None, "ssl_days_remaining": None}

    port = parsed.port or 443
    idna_hostname = hostname.encode("idna").decode("ascii")
    context = ssl._create_unverified_context()

    try:
        with socket.create_connection((idna_hostname, port), timeout=SSL_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=idna_hostname) as wrapped:
                der_cert = wrapped.getpeercert(binary_form=True)
        if not der_cert:
            return {"ssl_status": "missing", "ssl_expires_at": None, "ssl_days_remaining": None}

        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False) as temp:
                temp.write(pem_cert)
                temp_path = temp.name
            cert_info = ssl._ssl._test_decode_cert(temp_path)
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

        not_after = cert_info.get("notAfter")
        if not not_after:
            return {"ssl_status": "missing", "ssl_expires_at": None, "ssl_days_remaining": None}

        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (expires_at.date() - utc_now().date()).days
        if days_remaining < 0:
            status = "expired"
        elif days_remaining < SSL_WARNING_DAYS:
            status = "expiring"
        else:
            status = "valid"

        return {
            "ssl_status": status,
            "ssl_expires_at": to_iso(expires_at),
            "ssl_days_remaining": days_remaining,
        }
    except Exception:
        return {"ssl_status": "missing", "ssl_expires_at": None, "ssl_days_remaining": None}


def perform_site_check(site: sqlite3.Row) -> dict[str, Any]:
    http_result = check_http(site["url"])
    ssl_result = check_ssl(site["url"])
    return {
        **http_result,
        **ssl_result,
        "domain_days_remaining": days_until_date(site["domain_expires_at"]),
        "last_checked_at": iso_now(),
    }


def check_site_by_id(site_id: int) -> dict[str, Any] | None:
    site = get_site(site_id)
    if not site:
        return None
    result = perform_site_check(site)
    with get_db() as conn:
        conn.execute(
            """
            UPDATE sites
            SET availability_status = ?,
                http_status = ?,
                response_time_ms = ?,
                last_checked_at = ?,
                last_error = ?,
                ssl_status = ?,
                ssl_expires_at = ?,
                ssl_days_remaining = ?,
                domain_days_remaining = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                result["availability_status"],
                result["http_status"],
                result["response_time_ms"],
                result["last_checked_at"],
                result["last_error"],
                result["ssl_status"],
                result["ssl_expires_at"],
                result["ssl_days_remaining"],
                result["domain_days_remaining"],
                iso_now(),
                site_id,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return site_row_to_dict(row)


def run_all_checks() -> None:
    with get_db() as conn:
        site_ids = [row["id"] for row in conn.execute("SELECT id FROM sites ORDER BY id").fetchall()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        list(executor.map(check_site_by_id, site_ids))


def start_all_checks_async() -> bool:
    global CHECK_RUNNING
    if not CHECK_LOCK.acquire(blocking=False):
        return False
    CHECK_RUNNING = True

    def worker() -> None:
        global CHECK_RUNNING
        try:
            run_all_checks()
        finally:
            CHECK_RUNNING = False
            CHECK_LOCK.release()

    threading.Thread(target=worker, daemon=True).start()
    return True


def start_background_monitor() -> None:
    def loop() -> None:
        start_all_checks_async()
        while True:
            time.sleep(CHECK_INTERVAL_SECONDS)
            start_all_checks_async()

    threading.Thread(target=loop, daemon=True).start()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SiteDashboard/1.0"

    def _send_common_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'self'; form-action 'self'",
        )

    def _is_secure_request(self) -> bool:
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _send_json(self, status: int, data: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Некорректный Content-Length") from exc
        if length > 1_000_000:
            raise ValueError("Слишком большой запрос")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Некорректный JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON должен быть объектом")
        return payload

    def _cookies(self) -> dict[str, str]:
        header = self.headers.get("Cookie")
        if not header:
            return {}
        cookie = SimpleCookie()
        cookie.load(header)
        return {key: morsel.value for key, morsel in cookie.items()}

    def _current_session(self) -> sqlite3.Row | None:
        return get_session(self._cookies().get(SESSION_COOKIE))

    def _require_auth(self, require_csrf: bool = False) -> sqlite3.Row | None:
        session = self._current_session()
        if not session:
            self._send_error_json(HTTPStatus.UNAUTHORIZED, "Требуется вход")
            return None
        if require_csrf:
            csrf_token = self.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(csrf_token, session["csrf_token"]):
                self._send_error_json(HTTPStatus.FORBIDDEN, "Некорректный CSRF-токен")
                return None
        return session

    def _session_cookie_header(self, token: str, expires_at: datetime) -> str:
        secure = "; Secure" if self._is_secure_request() else ""
        return (
            f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age={SESSION_TTL_HOURS * 3600}; Expires={expires_at.strftime('%a, %d %b %Y %H:%M:%S GMT')}{secure}"
        )

    def _clear_session_cookie_header(self) -> str:
        return f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"

    def _serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            relative = "index.html"
        elif path.startswith("/static/"):
            relative = path.removeprefix("/static/")
        else:
            relative = "index.html"

        if relative.startswith("api/"):
            self._send_error_json(HTTPStatus.NOT_FOUND, "Не найдено")
            return

        target = (STATIC_DIR / relative).resolve()
        static_root = STATIC_DIR.resolve()
        if not target.is_relative_to(static_root):
            self._send_error_json(HTTPStatus.FORBIDDEN, "Доступ запрещён")
            return
        if not target.exists() or not target.is_file():
            target = STATIC_DIR / "index.html"

        body = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if target.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif target.suffix in {".css", ".js"}:
            content_type = f"text/{'css' if target.suffix == '.css' else 'javascript'}; charset=utf-8"

        self.send_response(HTTPStatus.OK)
        self._send_common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/me":
            session = self._require_auth()
            if not session:
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "user": {"username": session["username"]},
                    "csrf_token": session["csrf_token"],
                },
            )
            return

        if path == "/api/sites":
            if not self._require_auth():
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "sites": list_sites(),
                    "checking": CHECK_RUNNING,
                    "ssl_warning_days": SSL_WARNING_DAYS,
                    "domain_warning_days": DOMAIN_WARNING_DAYS,
                    "server_time": iso_now(),
                },
            )
            return

        if path.startswith("/api/"):
            self._send_error_json(HTTPStatus.NOT_FOUND, "Не найдено")
            return

        self._serve_static(path)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return

        if path == "/api/login":
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            with get_db() as conn:
                user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                self._send_error_json(HTTPStatus.UNAUTHORIZED, "Неверный логин или пароль")
                return
            cleanup_expired_sessions()
            token, csrf_token, expires_at = create_session(user["id"])
            self._send_json(
                HTTPStatus.OK,
                {"user": {"username": user["username"]}, "csrf_token": csrf_token},
                {"Set-Cookie": self._session_cookie_header(token, expires_at)},
            )
            return

        if path == "/api/logout":
            session = self._require_auth(require_csrf=True)
            if not session:
                return
            token = self._cookies().get(SESSION_COOKIE)
            if token:
                delete_session(token)
            self._send_json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": self._clear_session_cookie_header()})
            return

        if path == "/api/change-password":
            session = self._require_auth(require_csrf=True)
            if not session:
                return
            current_password = str(payload.get("current_password", ""))
            new_password = str(payload.get("new_password", ""))
            if len(new_password) < 8:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Новый пароль должен быть не короче 8 символов")
                return
            with get_db() as conn:
                user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
                if not user or not verify_password(current_password, user["password_hash"]):
                    self._send_error_json(HTTPStatus.UNAUTHORIZED, "Текущий пароль неверный")
                    return
                conn.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                    (hash_password(new_password), iso_now(), session["user_id"]),
                )
                conn.commit()
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        if path == "/api/sites":
            if not self._require_auth(require_csrf=True):
                return
            try:
                site = create_site(payload)
            except ValueError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self._send_json(HTTPStatus.CREATED, {"site": site})
            return

        if path == "/api/sites/check-all":
            if not self._require_auth(require_csrf=True):
                return
            started = start_all_checks_async()
            self._send_json(HTTPStatus.ACCEPTED, {"started": started, "checking": CHECK_RUNNING})
            return

        match = re.fullmatch(r"/api/sites/(\d+)/check", path)
        if match:
            if not self._require_auth(require_csrf=True):
                return
            site_id = int(match.group(1))
            site = check_site_by_id(site_id)
            if not site:
                self._send_error_json(HTTPStatus.NOT_FOUND, "Сайт не найден")
                return
            self._send_json(HTTPStatus.OK, {"site": site})
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, "Не найдено")

    def do_PUT(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        match = re.fullmatch(r"/api/sites/(\d+)", parsed.path)
        if not match:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Не найдено")
            return
        if not self._require_auth(require_csrf=True):
            return
        try:
            payload = self._read_json()
            site = update_site(int(match.group(1)), payload)
        except ValueError as exc:
            self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        if not site:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Сайт не найден")
            return
        self._send_json(HTTPStatus.OK, {"site": site})

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        match = re.fullmatch(r"/api/sites/(\d+)", parsed.path)
        if not match:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Не найдено")
            return
        if not self._require_auth(require_csrf=True):
            return
        deleted = delete_site_record(int(match.group(1)))
        if not deleted:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Сайт не найден")
            return
        self._send_json(HTTPStatus.OK, {"ok": True})

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_common_headers()
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {self.address_string()} {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Site availability and SSL dashboard")
    parser.add_argument("--host", default=os.environ.get("DASHBOARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DASHBOARD_PORT", "8000")))
    args = parser.parse_args()

    init_db()
    start_background_monitor()

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"Dashboard is running at http://{args.host}:{args.port}")
    print(f"Database: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
