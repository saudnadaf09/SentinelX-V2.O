"""Provider clients against a local fake server: proves honest status reporting without real API keys."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.domain import ai_providers as ap

KEY = "sk-test-SECRETKEY-12345"
SEEN: list[dict] = []
MODE = {"mode": "ok"}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        m = MODE["mode"]
        if m in ("401", "404", "429", "500"):
            self.send_response(int(m)); self.end_headers()
            self.wfile.write(f"error echo {KEY}".encode()); return  # a hostile server echoing the key back
        if m == "html":
            payload = b"<html>not json</html>"
        elif m == "empty":
            payload = json.dumps({"choices": [{"message": {"content": ""}}], "content": [], "candidates": [{"content": {"parts": []}}]}).encode()
        else:
            ok = {"choices": [{"message": {"content": '{"summary": "hello"}'}}],
                  "candidates": [{"content": {"parts": [{"text": '{"summary": "hello"}'}]}}],
                  "content": [{"type": "text", "text": '{"summary": "hello"}'}]}
            payload = json.dumps(ok).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(payload)


class ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Fake)
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        SEEN.clear(); MODE["mode"] = "ok"

    def test_each_provider_builds_the_official_request_shape(self):
        ap.call("openai", KEY, "gpt-4o-mini", "sys", "usr", base_url=self.url + "/v1")
        ap.call("gemini", KEY, "gemini-2.0-flash", "sys", "usr", base_url=self.url + "/v1beta")
        ap.call("anthropic", KEY, "claude-x", "sys", "usr", base_url=self.url)
        o, g, a = SEEN
        self.assertEqual(o["path"], "/v1/chat/completions")
        self.assertEqual(o["headers"]["authorization"], f"Bearer {KEY}")
        self.assertEqual(o["body"]["response_format"], {"type": "json_object"})
        self.assertEqual(g["path"], "/v1beta/models/gemini-2.0-flash:generateContent")
        self.assertEqual(g["headers"]["x-goog-api-key"], KEY)
        self.assertEqual(g["body"]["generationConfig"]["responseMimeType"], "application/json")
        self.assertEqual(a["path"], "/v1/messages")
        self.assertEqual((a["headers"]["x-api-key"], a["headers"]["anthropic-version"]), (KEY, "2023-06-01"))
        self.assertNotIn(KEY, json.dumps([o["body"], g["body"], a["body"]]))  # key only travels in headers

    def test_success_requires_real_answer(self):
        r = ap.test_connection("openai", KEY, "gpt-4o-mini", base_url=self.url + "/v1")
        self.assertTrue(r["ok"] and r["error_kind"] is None and r["latency_ms"] >= 0)
        MODE["mode"] = "empty"
        r = ap.test_connection("openai", KEY, "gpt-4o-mini", base_url=self.url + "/v1")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error_kind"], "bad_response")  # HTTP 200 with no answer is NOT a success
        MODE["mode"] = "html"
        self.assertFalse(ap.test_connection("gemini", KEY, "m", base_url=self.url)["ok"])

    def test_errors_are_classified_and_keys_scrubbed(self):
        for code, kind in (("401", "auth"), ("404", "model"), ("429", "rate_limit"), ("500", "server")):
            MODE["mode"] = code
            r = ap.test_connection("anthropic", KEY, "m", base_url=self.url)
            self.assertFalse(r["ok"], code)
            self.assertEqual(r["error_kind"], kind, code)
            self.assertNotIn(KEY, r["message"], "API key must never appear in a message")

    def test_unreachable_and_missing_key(self):
        r = ap.test_connection("openai", KEY, "m", base_url="http://127.0.0.1:9", timeout=2)
        self.assertEqual((r["ok"], r["error_kind"]), (False, "network"))
        r = ap.test_connection("openai", "", "m")
        self.assertEqual((r["ok"], r["error_kind"]), (False, "config"))
        with self.assertRaises(ap.ProviderError):
            ap.build_request("nope", KEY, "m", "s", "u")


if __name__ == "__main__":
    unittest.main()
