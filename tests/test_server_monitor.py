import copy
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import ValidationError
from api.services.server_monitor import ServerMonitor, MonitorThresholds, DEFAULT_THRESHOLDS
from test_domain_routing import app


class ServerMonitorTests(unittest.TestCase):
    def test_linux_cpu_delta_excludes_guest_and_detects_counter_reset(self):
        monitor = ServerMonitor()
        monitor._previous_cpu = (1000, 600)
        monitor._previous_cpu_at = 100
        with patch("api.services.server_monitor.time.monotonic", return_value=105), \
             patch.object(monitor, "_cpu_times", return_value=(1200, 650, 4)):
            self.assertEqual(monitor._cpu(), {"percent": 75.0, "cores": 4})
        with patch("api.services.server_monitor.sys.platform", "linux"), \
             patch("pathlib.Path.read_text", return_value="cpu  100 0 50 200 10 5 5 0 80 10\ncpu0 0\ncpu1 0\nintr 1\n"):
            self.assertEqual(monitor._cpu_times(), (370, 210, 2))
        monitor._previous_cpu = (2000, 1000)
        with patch("api.services.server_monitor.time.monotonic", return_value=106), \
             patch.object(monitor, "_cpu_times", return_value=(100, 50, 2)):
            self.assertIsNone(monitor._cpu()["percent"])

    def test_memory_available_and_legacy_fallback(self):
        monitor = ServerMonitor()
        for raw, available in (
            ("MemTotal: 1000 kB\nMemAvailable: 300 kB\n", 300),
            ("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 100 kB\nSReclaimable: 50 kB\nShmem: 50 kB\n", 300),
        ):
            with patch("api.services.server_monitor.sys.platform", "linux"), patch("pathlib.Path.read_text", return_value=raw):
                result = monitor._memory()
                self.assertEqual(result["percent"], 70)
                self.assertEqual(result["available"], available * 1024)

    def test_disk_percent_matches_df_reserved_capacity(self):
        with patch("api.services.server_monitor.shutil.disk_usage", return_value=SimpleNamespace(total=1000, used=800, free=100)):
            result = ServerMonitor()._disk()
            self.assertEqual(result["percent"], 88.9)
            self.assertEqual(result["available"], 100)

    def test_concurrent_snapshots_share_cache_and_copy_results(self):
        monitor = ServerMonitor()
        with patch.object(monitor, "_cpu", return_value={"percent": 12}) as cpu, \
             patch.object(monitor, "_memory", side_effect=OSError("fixture")), \
             patch.object(monitor, "_disk", return_value={"percent": 90}), \
             patch("api.services.server_monitor.time.monotonic", return_value=100):
            with ThreadPoolExecutor(max_workers=6) as pool:
                rows = list(pool.map(lambda _: monitor.snapshot(), range(12)))
            cpu.assert_called_once()
            self.assertIsNone(rows[0]["memory"]["percent"])
            rows[0]["cpu"]["percent"] = 100
            self.assertEqual(monitor.snapshot()["cpu"]["percent"], 12)
        with patch.object(monitor, "_cpu", return_value={"percent": 20}) as cpu, \
             patch.object(monitor, "_memory", return_value={"percent": 10}), \
             patch.object(monitor, "_disk", return_value={"percent": 91}), \
             patch("api.services.server_monitor.time.monotonic", return_value=106):
            self.assertEqual(monitor.snapshot()["cpu"]["percent"], 20)
            cpu.assert_called_once()

    def test_threshold_rejects_missing_extra_non_numeric_nan_and_unordered(self):
        for value in ("90", True, float("nan"), float("inf"), -1, 101):
            draft = copy.deepcopy(DEFAULT_THRESHOLDS)
            draft["cpu"]["warning"] = value
            with self.assertRaises(ValidationError):
                MonitorThresholds.model_validate(draft)
        for value in (95, 99):
            draft = copy.deepcopy(DEFAULT_THRESHOLDS)
            draft["cpu"]["warning"] = value
            with self.assertRaises(ValidationError):
                MonitorThresholds.model_validate(draft)
        with self.assertRaises(ValidationError):
            MonitorThresholds.model_validate({"cpu": DEFAULT_THRESHOLDS["cpu"]})
        with self.assertRaises(ValidationError):
            MonitorThresholds.model_validate({**DEFAULT_THRESHOLDS, "extra": {}})

    def test_api_requires_console_session_and_persists_thresholds(self):
        client = TestClient(app.app)
        store = {}
        with patch.object(app, "admin_ok", side_effect=lambda token: token == "fixture-session"), \
             patch.object(app, "setting_get", side_effect=store.get), \
             patch.object(app, "setting_set", side_effect=store.__setitem__), \
             patch.object(app.server_monitor, "snapshot", return_value={"cpu": {"percent": 1}}) as sampler:
            for token in ("", "ordinary-api-key", "admin-api-key"):
                self.assertEqual(client.get("/api/v1/system/monitor", headers={"X-API-Key": token}).status_code, 401)
                self.assertEqual(client.put("/api/v1/system/monitor/thresholds", headers={"X-API-Key": token}, json=DEFAULT_THRESHOLDS).status_code, 401)
            sampler.assert_not_called()
            headers = {"X-API-Key": "fixture-session"}
            response = client.get("/api/v1/system/monitor", headers=headers)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.json()["thresholds"], DEFAULT_THRESHOLDS)
            draft = copy.deepcopy(DEFAULT_THRESHOLDS)
            draft["disk"] = {"warning": 75, "critical": 90}
            response = client.put("/api/v1/system/monitor/thresholds", headers=headers, json=draft)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(client.get("/api/v1/system/monitor", headers=headers).json()["thresholds"], draft)
            bad = copy.deepcopy(draft)
            bad["cpu"]["warning"] = 99
            self.assertEqual(client.put("/api/v1/system/monitor/thresholds", headers=headers, json=bad).status_code, 422)
            self.assertEqual(client.get("/api/v1/system/monitor", headers=headers).json()["thresholds"], draft)
            store["server_monitor_thresholds"] = "{broken"
            response = client.get("/api/v1/system/monitor", headers=headers).json()
            self.assertEqual(response["thresholds"], DEFAULT_THRESHOLDS)
            self.assertTrue(response["settings_error"])


if __name__ == "__main__":
    unittest.main()
