import json
import os
import unittest

os.environ.setdefault("GITHUB_CLIENT_ID", "test-client")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "test-secret")
os.environ.setdefault("SESSION_SECRET", "x" * 64)
os.environ.setdefault("PUBLIC_BASE_URL", "https://save.example.test")
os.environ.setdefault("FRONTEND_ORIGIN", "https://davidetonelli.github.io")

from fastapi.testclient import TestClient
from app import app, validate_character, render_data_js, resolve_character, safe_return_to, parse_update_result


def valid_payload():
    return {
        "dataVersion": 1,
        "character": {"name": "Test", "race": "Umano", "level": 3},
        "abilities": [],
        "spells": [{"id": "luce", "name": "Luce", "level": 0, "summary": "Illumina."}],
        "traits": [],
        "slots": [],
    }


class BackendTests(unittest.TestCase):
    def test_update_result_keeps_file_sha_separate_from_commit_sha(self):
        result = parse_update_result({"content": {"sha": "blob-sha"}, "commit": {"sha": "commit-sha"}}, "data.js")
        self.assertEqual(result, {"ok": "true", "commit": "commit-sha", "sha": "blob-sha", "path": "data.js"})

    def test_return_path_is_limited_to_character_pages(self):
        self.assertEqual(safe_return_to("/dnd/"), "/dnd/")
        self.assertEqual(safe_return_to("/dnd/ossian/"), "/dnd/ossian/")
        self.assertEqual(safe_return_to("https://evil.example/"), "/dnd/")

    def test_only_known_character_files_are_resolved(self):
        self.assertEqual(resolve_character("olga"), ("data.js", "OLGA_DATA"))
        self.assertEqual(resolve_character("ossian"), ("ossian/data.js", "OSSIAN_DATA"))
        with self.assertRaises(ValueError):
            resolve_character("../../README")

    def test_payload_requires_collections_and_unique_spell_ids(self):
        clean = validate_character(valid_payload())
        self.assertEqual(clean["character"]["name"], "Test")
        broken = valid_payload()
        broken["spells"].append(dict(broken["spells"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate spell id"):
            validate_character(broken)

    def test_renderer_emits_only_data_assignment(self):
        text = render_data_js("OLGA_DATA", valid_payload())
        self.assertTrue(text.startswith("window.OLGA_DATA="))
        self.assertTrue(text.endswith(";\n"))
        parsed = json.loads(text.removeprefix("window.OLGA_DATA=").removesuffix(";\n"))
        self.assertEqual(parsed["spells"][0]["name"], "Luce")

    def test_health_and_cors_are_available_without_authentication(self):
        client = TestClient(app)
        response = client.get("/health", headers={"Origin": "https://davidetonelli.github.io"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        self.assertEqual(response.headers["access-control-allow-origin"], "https://davidetonelli.github.io")

    def test_save_requires_authenticated_owner(self):
        client = TestClient(app)
        response = client.post("/api/save/olga", json={"data": valid_payload(), "sha": "abc"})
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
