import unittest
from pathlib import Path

from cve_hunter.tools.db_spec import extract_database_execution_spec, extract_sql_statements
from cve_hunter.tools.local_kb import search_local_kb


class DbSpecExtractionTests(unittest.TestCase):
    def test_resolve_database_target_from_http_url(self):
        from cve_hunter.tools.db_spec import resolve_database_target

        dsn = resolve_database_target(
            engine="postgres",
            env_target="http://127.0.0.1:5432",
            user="postgres",
            password="postgres",
            database="postgres",
        )
        self.assertEqual(dsn, "postgres://postgres:postgres@127.0.0.1:5432/postgres")

        dsn_tcp = resolve_database_target(
            engine="postgres",
            env_target="tcp://127.0.0.1:5433",
            user="postgres",
            password="postgres",
            database="postgres",
        )
        self.assertEqual(dsn_tcp, "postgres://postgres:postgres@127.0.0.1:5433/postgres")

        dsn2 = resolve_database_target(
            engine="mysql",
            env_target="127.0.0.1:3306",
            user="root",
            password="123456",
            database="test",
        )
        self.assertEqual(dsn2, "mysql://root:123456@127.0.0.1:3306/test")

    def test_extract_postgres_vulhub_readme(self):
        text = Path("third_party/vulhub/postgres/CVE-2019-9193/README.zh-cn.md").read_text(encoding="utf-8")
        statements = extract_sql_statements(text)
        self.assertTrue(any("COPY cmd_exec FROM PROGRAM" in s for s in statements))
        self.assertFalse(any("docker compose" in s.lower() for s in statements))

        spec = extract_database_execution_spec(text, cve_id="CVE-2019-9193")
        self.assertIsNotNone(spec)
        assert spec is not None
        self.assertEqual(spec["protocol"], "database")
        self.assertEqual(spec["engine"], "postgres")
        self.assertIn("postgres://", spec["target"])
        self.assertTrue(any("CREATE TABLE" in s.upper() for s in spec["schema_sql"]))
        self.assertTrue(any("FROM PROGRAM" in s.upper() for s in spec["trigger_sql"]))
        self.assertEqual(spec["oracle"]["type"], "result_contains")
        self.assertEqual(spec["oracle"]["expect"], "uid=")

    def test_local_kb_returns_execution_spec_for_postgres_cve(self):
        result = search_local_kb("CVE-2019-9193")
        self.assertTrue(result.get("found"))
        self.assertTrue(result.get("execution_spec"))
        self.assertEqual(result["source"], "local_kb_vulhub_sql")
        self.assertEqual(result["execution_spec"]["protocol"], "database")

    def test_extract_mysql_auth_bypass_cve_2012_2122(self):
        text = Path("third_party/vulhub/mysql/CVE-2012-2122/README.zh-cn.md").read_text(encoding="utf-8")
        spec = extract_database_execution_spec(text, cve_id="CVE-2012-2122", default_engine="mysql")
        self.assertIsNotNone(spec)
        assert spec is not None
        self.assertEqual(spec["protocol"], "database")
        self.assertEqual(spec["engine"], "mysql")
        self.assertEqual(spec["action"], "auth_bypass")
        self.assertEqual(spec["oracle"]["type"], "auth_success")
        self.assertEqual(spec["auth_bypass"]["username"], "root")
        self.assertEqual(spec["auth_bypass"]["password"], "wrong")
        self.assertGreaterEqual(int(spec["auth_bypass"]["max_attempts"]), 1000)

    def test_local_kb_returns_execution_spec_for_mysql_auth_bypass(self):
        result = search_local_kb("CVE-2012-2122")
        self.assertTrue(result.get("found"))
        self.assertTrue(result.get("execution_spec"))
        self.assertEqual(result["execution_spec"]["action"], "auth_bypass")
        self.assertEqual(result["execution_spec"]["oracle"]["type"], "auth_success")

    def test_extract_postgres_search_path_cve_2018_1058(self):
        from cve_hunter.tools.db_spec import extract_compose_db_credentials

        text = Path("third_party/vulhub/postgres/CVE-2018-1058/README.zh-cn.md").read_text(encoding="utf-8")
        creds = extract_compose_db_credentials("third_party/vulhub/postgres/CVE-2018-1058")
        self.assertEqual(creds.get("postgres_password"), "vulhub_secret")
        self.assertEqual(creds.get("app_user"), "vulhub")
        spec = extract_database_execution_spec(
            text,
            cve_id="CVE-2018-1058",
            default_engine="postgres",
            compose_credentials=creds,
        )
        self.assertIsNotNone(spec)
        assert spec is not None
        self.assertEqual(spec["action"], "multi_session")
        self.assertEqual(len(spec["sessions"]), 2)
        self.assertEqual(spec["sessions"][0]["user"], "vulhub")
        self.assertEqual(spec["sessions"][1]["user"], "postgres")
        self.assertEqual(spec["sessions"][1]["password"], "vulhub_secret")
        self.assertEqual(spec["oracle"]["type"], "result_contains")
        self.assertIn("cve-2018-1058-triggered", spec["oracle"]["expect"])
        self.assertIn("vulhub_secret", spec["target"])

    def test_local_kb_returns_multi_session_for_1058(self):
        result = search_local_kb("CVE-2018-1058")
        self.assertTrue(result.get("found"))
        self.assertTrue(result.get("execution_spec"))
        self.assertEqual(result["execution_spec"]["action"], "multi_session")


if __name__ == "__main__":
    unittest.main()
