import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import traceback
import webbrowser
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("ORGANIZA_DB", ROOT / "organiza.sqlite"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "3000"))
SESSION_SECONDS = 7 * 24 * 60 * 60
PASSWORD_N = 32768
PASSWORD_R = 8
PASSWORD_P = 1
PASSWORD_MAXMEM = 64 * 1024 * 1024
CATEGORIES = {"Trabalho", "Pessoal", "Estudos", "Saúde", "Outros"}
PRIORITIES = {"Alta", "Média", "Baixa"}
STATUSES = {"todo", "doing", "done"}
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
RATE_LOCK = threading.Lock()
AUTH_ATTEMPTS = {}


def connect_database():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


@contextmanager
def database():
    connection = connect_database()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                due_date TEXT NOT NULL DEFAULT '',
                priority TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'todo',
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS tasks_by_user ON tasks(user_id, due_date);
            """
        )


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_N,
        r=PASSWORD_R,
        p=PASSWORD_P,
        dklen=64,
        maxmem=PASSWORD_MAXMEM,
    )
    return f"scrypt${PASSWORD_N}${PASSWORD_R}${PASSWORD_P}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=PASSWORD_MAXMEM,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def normalize_task(row):
    return {
        "id": str(row["id"]),
        "title": row["title"],
        "description": row["description"],
        "dueDate": row["due_date"],
        "priority": row["priority"],
        "category": row["category"],
        "status": row["status"],
        "createdAt": row["created_at"],
        "completedAt": row["completed_at"],
    }


def validate_task(body):
    if not isinstance(body, dict):
        return None
    title = body.get("title")
    description = body.get("description", "")
    due_date = body.get("dueDate", "")
    priority = body.get("priority")
    category = body.get("category")
    if not isinstance(title, str) or not isinstance(description, str):
        return None
    title = title.strip()
    description = description.strip()
    if not title or len(title) > 100 or len(description) > 300:
        return None
    if due_date is None:
        due_date = ""
    if not isinstance(due_date, str):
        return None
    if due_date:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", due_date):
            return None
        try:
            time.strptime(due_date, "%Y-%m-%d")
        except ValueError:
            return None
    if (
        not isinstance(priority, str)
        or not isinstance(category, str)
        or priority not in PRIORITIES
        or category not in CATEGORIES
    ):
        return None
    return {
        "title": title,
        "description": description,
        "dueDate": due_date,
        "priority": priority,
        "category": category,
    }


class OrganizerServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class OrganizerHandler(BaseHTTPRequestHandler):
    server_version = "Organiza"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Tamanho da solicitação inválido.") from None
        if length < 0 or length > 10 * 1024:
            raise ValueError("A solicitação excede o tamanho permitido.")
        raw_body = self.rfile.read(length)
        try:
            return json.loads(raw_body) if raw_body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("A solicitação contém JSON inválido.") from None

    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers:
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_empty(self, status, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        if extra_headers:
            for name, value in extra_headers:
                self.send_header(name, value)
        self.end_headers()

    def error(self, status, message):
        self.send_json(status, {"error": message})

    def get_session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        morsel = cookie.get("organiza_session")
        if not morsel or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", morsel.value):
            return ""
        return morsel.value

    def get_user(self, db):
        token = self.get_session_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        session = db.execute(
            """
            SELECT users.id, users.email, sessions.expires_at
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if session is None:
            return None
        if session["expires_at"] <= int(time.time() * 1000):
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            db.commit()
            return None
        return {"id": session["id"], "email": session["email"]}

    def require_same_origin(self):
        origin = self.headers.get("Origin")
        expected = f"http://{self.headers.get('Host', '')}"
        if not origin or origin.rstrip("/") != expected:
            self.error(HTTPStatus.FORBIDDEN, "Origem da solicitação não autorizada.")
            return False
        return True

    def allow_auth_attempt(self):
        now = time.time()
        client = self.client_address[0]
        with RATE_LOCK:
            attempts = [stamp for stamp in AUTH_ATTEMPTS.get(client, []) if now - stamp < 900]
            if len(attempts) >= 8:
                AUTH_ATTEMPTS[client] = attempts
                self.error(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "Muitas tentativas. Aguarde alguns minutos e tente novamente.",
                )
                return False
            attempts.append(now)
            AUTH_ATTEMPTS[client] = attempts
        return True

    def create_session(self, db, user_id):
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time() * 1000) + SESSION_SECONDS * 1000
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time() * 1000),))
        db.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expires_at),
        )
        db.commit()
        return (
            f"organiza_session={token}; HttpOnly; SameSite=Strict; Path=/; "
            f"Max-Age={SESSION_SECONDS}"
        )

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            try:
                content = (ROOT / "Organizador.html").read_bytes()
            except OSError:
                self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Não foi possível carregar a página.")
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)
            return

        try:
            with database() as db:
                user = self.get_user(db)
                if path == "/api/auth/session":
                    self.send_json(HTTPStatus.OK, {"user": user})
                    return
                if path == "/api/tasks":
                    if user is None:
                        self.error(HTTPStatus.UNAUTHORIZED, "Entre na sua conta para continuar.")
                        return
                    rows = db.execute(
                        """
                        SELECT id, title, description, due_date, priority, category,
                               status, created_at, completed_at
                        FROM tasks WHERE user_id = ?
                        ORDER BY due_date = '', due_date, created_at DESC
                        """,
                        (user["id"],),
                    ).fetchall()
                    self.send_json(HTTPStatus.OK, {"tasks": [normalize_task(row) for row in rows]})
                    return
        except sqlite3.Error:
            self.log_error("Erro no banco SQLite:\n%s", traceback.format_exc())
            self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Erro ao acessar os dados. Tente novamente.")
            return
        self.error(HTTPStatus.NOT_FOUND, "Página não encontrada.")

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/auth/logout":
            if not self.require_same_origin():
                return
            try:
                token = self.get_session_token()
                if token:
                    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
                    with database() as db:
                        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                        db.commit()
                self.send_empty(
                    HTTPStatus.NO_CONTENT,
                    [("Set-Cookie", "organiza_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")],
                )
            except (sqlite3.Error, UnicodeEncodeError):
                self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Não foi possível encerrar a sessão.")
            return

        if path not in {"/api/auth/login", "/api/auth/register", "/api/tasks"}:
            self.error(HTTPStatus.NOT_FOUND, "Página não encontrada.")
            return
        if not self.require_same_origin():
            return
        if path.startswith("/api/auth/") and not self.allow_auth_attempt():
            return
        try:
            body = self.read_body()
        except ValueError as error:
            self.error(HTTPStatus.BAD_REQUEST, str(error))
            return

        if path in {"/api/auth/login", "/api/auth/register"}:
            self.handle_auth(path, body)
            return
        self.handle_create_task(body)

    def handle_auth(self, path, body):
        if not isinstance(body, dict):
            self.error(HTTPStatus.BAD_REQUEST, "Confira o e-mail e a senha.")
            return
        email = body.get("email", "")
        password = body.get("password", "")
        if not isinstance(email, str) or not isinstance(password, str):
            self.error(HTTPStatus.BAD_REQUEST, "Confira o e-mail e a senha.")
            return
        email = email.strip().lower()
        if path == "/api/auth/register":
            if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
                self.error(HTTPStatus.BAD_REQUEST, "Informe um e-mail válido.")
                return
            if len(password) < 8 or len(password) > 128:
                self.error(HTTPStatus.BAD_REQUEST, "A senha deve ter entre 8 e 128 caracteres.")
                return
        elif len(email) > 254 or not password or len(password) > 128:
            self.error(HTTPStatus.UNAUTHORIZED, "E-mail ou senha inválidos.")
            return
        try:
            with database() as db:
                if path == "/api/auth/register":
                    password_hash = hash_password(password)
                    try:
                        result = db.execute(
                            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                            (email, password_hash, int(time.time() * 1000)),
                        )
                    except sqlite3.IntegrityError:
                        self.error(
                            HTTPStatus.CONFLICT,
                            "Não foi possível criar a conta com esse e-mail.",
                        )
                        return
                    cookie = self.create_session(db, result.lastrowid)
                    self.send_json(
                        HTTPStatus.CREATED,
                        {"user": {"email": email}},
                        [("Set-Cookie", cookie)],
                    )
                    return

                user = db.execute(
                    "SELECT id, email, password_hash FROM users WHERE email = ?",
                    (email,),
                ).fetchone()
                if user is None:
                    hash_password(password)
                    self.error(HTTPStatus.UNAUTHORIZED, "E-mail ou senha inválidos.")
                    return
                if not verify_password(password, user["password_hash"]):
                    self.error(HTTPStatus.UNAUTHORIZED, "E-mail ou senha inválidos.")
                    return
                cookie = self.create_session(db, user["id"])
                self.send_json(
                    HTTPStatus.OK,
                    {"user": {"email": user["email"]}},
                    [("Set-Cookie", cookie)],
                )
        except sqlite3.Error:
            self.log_error("Erro no banco SQLite:\n%s", traceback.format_exc())
            self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Erro ao acessar os dados. Tente novamente.")
        except (OSError, ValueError):
            self.log_error("Erro ao verificar a senha:\n%s", traceback.format_exc())
            self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Não foi possível validar a senha.")

    def handle_create_task(self, body):
        if not self.is_authenticated():
            return
        task = validate_task(body)
        if task is None:
            self.error(
                HTTPStatus.BAD_REQUEST,
                "Confira o nome, o prazo, a prioridade e a categoria.",
            )
            return
        try:
            with database() as db:
                user = self.get_user(db)
                if user is None:
                    self.error(HTTPStatus.UNAUTHORIZED, "Entre na sua conta para continuar.")
                    return
                result = db.execute(
                    """
                    INSERT INTO tasks (
                        user_id, title, description, due_date, priority, category, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'todo', ?)
                    """,
                    (
                        user["id"],
                        task["title"],
                        task["description"],
                        task["dueDate"],
                        task["priority"],
                        task["category"],
                        int(time.time() * 1000),
                    ),
                )
                row = db.execute(
                    """
                    SELECT id, title, description, due_date, priority, category,
                           status, created_at, completed_at
                    FROM tasks WHERE id = ? AND user_id = ?
                    """,
                    (result.lastrowid, user["id"]),
                ).fetchone()
                self.send_json(HTTPStatus.CREATED, {"task": normalize_task(row)})
        except sqlite3.Error:
            self.log_error("Erro ao criar tarefa:\n%s", traceback.format_exc())
            self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Não foi possível salvar a tarefa.")

    def is_authenticated(self):
        try:
            with database() as db:
                if self.get_user(db) is not None:
                    return True
        except sqlite3.Error:
            self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Erro ao verificar sua sessão.")
            return False
        self.error(HTTPStatus.UNAUTHORIZED, "Entre na sua conta para continuar.")
        return False

    def do_PUT(self):
        self.handle_task_update("details")

    def do_PATCH(self):
        self.handle_task_update("status")

    def handle_task_update(self, update_type):
        match = re.fullmatch(r"/api/tasks/(\d+)", urlsplit(self.path).path)
        if not match:
            self.error(HTTPStatus.NOT_FOUND, "Tarefa não encontrada.")
            return
        if not self.require_same_origin():
            return
        if not self.is_authenticated():
            return
        try:
            body = self.read_body()
        except ValueError as error:
            self.error(HTTPStatus.BAD_REQUEST, str(error))
            return

        try:
            with database() as db:
                user = self.get_user(db)
                if user is None:
                    self.error(HTTPStatus.UNAUTHORIZED, "Entre na sua conta para continuar.")
                    return
                task_id = int(match.group(1))
                if update_type == "details":
                    task = validate_task(body)
                    if task is None:
                        self.error(
                            HTTPStatus.BAD_REQUEST,
                            "Confira o nome, o prazo, a prioridade e a categoria.",
                        )
                        return
                    result = db.execute(
                        """
                        UPDATE tasks
                        SET title = ?, description = ?, due_date = ?, priority = ?, category = ?
                        WHERE id = ? AND user_id = ?
                        """,
                        (
                            task["title"],
                            task["description"],
                            task["dueDate"],
                            task["priority"],
                            task["category"],
                            task_id,
                            user["id"],
                        ),
                    )
                    if not result.rowcount:
                        self.error(HTTPStatus.NOT_FOUND, "Tarefa não encontrada.")
                        return
                else:
                    status = body.get("status") if isinstance(body, dict) else None
                    if not isinstance(status, str) or status not in STATUSES:
                        self.error(HTTPStatus.BAD_REQUEST, "Status de tarefa inválido.")
                        return
                    current = db.execute(
                        "SELECT status, completed_at FROM tasks WHERE id = ? AND user_id = ?",
                        (task_id, user["id"]),
                    ).fetchone()
                    if current is None:
                        self.error(HTTPStatus.NOT_FOUND, "Tarefa não encontrada.")
                        return
                    completed_at = current["completed_at"]
                    if status == "done" and current["status"] != "done":
                        completed_at = int(time.time() * 1000)
                    elif status != "done":
                        completed_at = None
                    db.execute(
                        """
                        UPDATE tasks SET status = ?, completed_at = ?
                        WHERE id = ? AND user_id = ?
                        """,
                        (status, completed_at, task_id, user["id"]),
                    )
                row = db.execute(
                    """
                    SELECT id, title, description, due_date, priority, category,
                           status, created_at, completed_at
                    FROM tasks WHERE id = ? AND user_id = ?
                    """,
                    (task_id, user["id"]),
                ).fetchone()
                self.send_json(HTTPStatus.OK, {"task": normalize_task(row)})
        except sqlite3.Error:
            self.log_error("Erro ao atualizar tarefa:\n%s", traceback.format_exc())
            self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Não foi possível atualizar a tarefa.")

    def do_DELETE(self):
        match = re.fullmatch(r"/api/tasks/(\d+)", urlsplit(self.path).path)
        if not match:
            self.error(HTTPStatus.NOT_FOUND, "Tarefa não encontrada.")
            return
        if not self.require_same_origin():
            return
        if not self.is_authenticated():
            return
        try:
            with database() as db:
                user = self.get_user(db)
                if user is None:
                    self.error(HTTPStatus.UNAUTHORIZED, "Entre na sua conta para continuar.")
                    return
                result = db.execute(
                    "DELETE FROM tasks WHERE id = ? AND user_id = ?",
                    (int(match.group(1)), user["id"]),
                )
                if not result.rowcount:
                    self.error(HTTPStatus.NOT_FOUND, "Tarefa não encontrada.")
                    return
                self.send_empty(HTTPStatus.NO_CONTENT)
        except sqlite3.Error:
            self.log_error("Erro ao excluir tarefa:\n%s", traceback.format_exc())
            self.error(HTTPStatus.INTERNAL_SERVER_ERROR, "Não foi possível excluir a tarefa.")


def main():
    initialize_database()
    server = OrganizerServer((HOST, PORT), OrganizerHandler)
    print(f"Organiza disponível em http://{HOST}:{PORT}")
    print("Mantenha esta janela aberta enquanto usa o organizador.")
    threading.Timer(0.8, lambda: webbrowser.open(f"http://{HOST}:{PORT}")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando o Organiza...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
