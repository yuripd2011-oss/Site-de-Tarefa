import http.client
import json
import tempfile
import threading
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

import server as organizer


class OrganizerServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_directory = tempfile.TemporaryDirectory()
        cls.previous_database = organizer.DATABASE
        organizer.DATABASE = Path(cls.temp_directory.name) / "test.sqlite"
        organizer.initialize_database()
        cls.httpd = organizer.OrganizerServer(
            ("127.0.0.1", 0), organizer.OrganizerHandler
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)
        organizer.DATABASE = cls.previous_database
        cls.temp_directory.cleanup()

    def request(self, method, path, body=None, cookie=None, include_origin=True):
        parsed = urlsplit(self.origin)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port)
        headers = {}
        if include_origin:
            headers["Origin"] = self.origin
        if cookie:
            headers["Cookie"] = cookie
        encoded_body = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            encoded_body = json.dumps(body).encode("utf-8")
        connection.request(method, path, body=encoded_body, headers=headers)
        response = connection.getresponse()
        result = response.read()
        response_headers = dict(response.getheaders())
        connection.close()
        decoded = (
            json.loads(result.decode("utf-8"))
            if result and response_headers.get("Content-Type", "").startswith("application/json")
            else result
        )
        return response.status, decoded, response_headers

    def register(self, email, password="secure-password"):
        status, body, headers = self.request(
            "POST",
            "/api/auth/register",
            {"email": email, "password": password},
        )
        self.assertEqual(status, 201, body)
        cookie = SimpleCookie()
        cookie.load(headers["Set-Cookie"])
        return f"organiza_session={cookie['organiza_session'].value}"

    def test_accounts_cannot_read_or_change_each_others_tasks(self):
        status, body, _ = self.request("GET", "/api/tasks")
        self.assertEqual(status, 401, body)

        alice_cookie = self.register("alice@example.com")
        status, result, _ = self.request(
            "POST",
            "/api/tasks",
            {
                "title": "Plano privado",
                "description": "",
                "dueDate": "",
                "priority": "Alta",
                "category": "Pessoal",
            },
            cookie=alice_cookie,
        )
        self.assertEqual(status, 201, result)
        task_id = result["task"]["id"]

        bob_cookie = self.register("bob@example.com")
        status, result, _ = self.request("GET", "/api/tasks", cookie=bob_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(result["tasks"], [])

        status, _, _ = self.request(
            "PUT",
            f"/api/tasks/{task_id}",
            {
                "title": "Tentativa",
                "description": "",
                "dueDate": "",
                "priority": "Alta",
                "category": "Pessoal",
            },
            cookie=bob_cookie,
        )
        self.assertEqual(status, 404)

        status, _, _ = self.request(
            "DELETE", f"/api/tasks/{task_id}", cookie=bob_cookie
        )
        self.assertEqual(status, 404)

        status, result, _ = self.request("GET", "/api/tasks", cookie=alice_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(result["tasks"][0]["title"], "Plano privado")

    def test_register_validates_password_and_rejects_missing_origin(self):
        status, _, _ = self.request(
            "POST",
            "/api/auth/register",
            {"email": "no-origin@example.com", "password": "secure-password"},
            include_origin=False,
        )
        self.assertEqual(status, 403)

        status, _, _ = self.request(
            "POST",
            "/api/auth/register",
            {"email": "short@example.com", "password": "short"},
        )
        self.assertEqual(status, 400)

    def test_login_status_updates_and_logout(self):
        alice_cookie = self.register("login@example.com")
        status, result, _ = self.request(
            "POST",
            "/api/tasks",
            {
                "title": "Concluir relatório",
                "description": "",
                "dueDate": "",
                "priority": "Média",
                "category": "Trabalho",
            },
            cookie=alice_cookie,
        )
        self.assertEqual(status, 201)
        task_id = result["task"]["id"]

        status, _, headers = self.request(
            "POST",
            "/api/auth/login",
            {"email": "login@example.com", "password": "secure-password"},
        )
        self.assertEqual(status, 200)
        cookie = SimpleCookie()
        cookie.load(headers["Set-Cookie"])
        login_cookie = f"organiza_session={cookie['organiza_session'].value}"

        status, result, _ = self.request(
            "PATCH",
            f"/api/tasks/{task_id}",
            {"status": "done"},
            cookie=login_cookie,
        )
        self.assertEqual(status, 200)
        completed_at = result["task"]["completedAt"]
        self.assertIsNotNone(completed_at)

        status, result, _ = self.request(
            "PATCH",
            f"/api/tasks/{task_id}",
            {"status": "done"},
            cookie=login_cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["task"]["completedAt"], completed_at)

        status, _, _ = self.request(
            "POST", "/api/auth/logout", cookie=login_cookie
        )
        self.assertEqual(status, 204)
        status, _, _ = self.request("GET", "/api/tasks", cookie=login_cookie)
        self.assertEqual(status, 401)

    def test_rejects_invalid_task_data(self):
        cookie = self.register("invalid-task@example.com")
        status, _, _ = self.request(
            "POST",
            "/api/tasks",
            {
                "title": "Data inválida",
                "description": "",
                "dueDate": "2026-02-31",
                "priority": "Urgente",
                "category": "Pessoal",
            },
            cookie=cookie,
        )
        self.assertEqual(status, 400)

    def test_serves_html_from_local_server(self):
        status, body, headers = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Organizador de tarefas", body)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
