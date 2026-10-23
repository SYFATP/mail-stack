"""dynv6 wire contract and the existing durable DNS workflow."""
import copy
import json
import unittest
from unittest.mock import patch
import test_domain_control as base
from api.providers.dns.dynv6 import Dynv6DNS
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict
from api.services.dns_inventory import scoped_inventory


class Dynv6Wire:
    def __init__(self):
        self.calls, self.records = [], []
        self.zones = [{"id": 100, "name": "example.test", "ipv4address": "", "ipv6prefix": ""}]
        self.sequence, self.failure = 200, ""

    def request(self, method, base_url, path, **kw):
        self.calls.append((method, base_url, path, copy.deepcopy(kw)))
        assert base_url == "https://dynv6.com"
        assert kw["headers"]["Authorization"] == "Bearer " + base.TOKEN
        if method == "GET" and path == "/api/v2/zones":
            return copy.deepcopy(self.zones)
        if method == "GET" and path == "/api/v2/zones/100":
            return copy.deepcopy(next(z for z in self.zones if z["id"] == 100))
        if method == "GET" and path == "/api/v2/zones/100/records":
            return copy.deepcopy(self.records)
        if self.failure == "rate" and method == "POST":
            self.failure = ""
            raise ProviderError("provider_http_429", uncertain=True, retry_after=1200)
        if method in {"POST", "PATCH"} and path.startswith("/api/v2/zones/100/records"):
            body = copy.deepcopy(kw["body"])
            if method == "POST":
                self.sequence += 1
                row = {"id": self.sequence, "zoneID": 100, "flags": 0, "weight": 0, **body}
                self.records.append(row)
            else:
                row = next(r for r in self.records if str(r["id"]) == path.rsplit("/", 1)[-1])
                row.update(body)
            if self.failure == "timeout":
                self.failure = ""
                raise ProviderError("provider_transport_or_json_error", uncertain=True)
            return copy.deepcopy(row)
        raise AssertionError((method, path))


class Dynv6Tests(unittest.TestCase):
    def setUp(self):
        self.case = base.P2Tests(methodName="runTest")
        self.case.setUp()
        self.m = self.case.manager
        self.wire = Dynv6Wire()
        self.m.http = self.wire
        self.case.domain(receive_subdomains=False, enabled=False)
        self.credential = self.m.add_dns_credential("dynv6", None, "dynv6 fixture", {"api_token": base.TOKEN})
        self.m.bind_dns_credential("example.test", self.credential["id"])
        self.enterContext(patch("api.services.readiness_refresh.smtp_submission_check",
                                return_value={"status": "passed", "detail": "fixture_smtp_envelope_no_data"}))

    def tearDown(self):
        self.case.tearDown()

    def writes(self):
        return [c for c in self.wire.calls if c[0] in {"POST", "PATCH"}]

    def apply(self, key="dynv6-apply-fixture"):
        plan = self.m.dns.preview("example.test")
        self.assertTrue(plan["executable"], plan["conflicts"])
        job = self.m.dns.enqueue("example.test", plan["id"], key)
        self.m.run_once()
        return self.m.jobs.get(job["id"])

    def test_api_accepts_token_encrypted_and_redacts_projection(self):
        response = self.case.client.post("/api/v1/dns-credentials", headers=self.case.headers,
            json={"provider": "dynv6", "label": "second fixture", "secret": {"api_token": base.TOKEN}})
        self.assertEqual(response.status_code, 201)
        self.assertNotIn(base.TOKEN, response.text)
        c = self.m.db()
        try:
            saved = c.execute("SELECT ciphertext FROM dns_credentials WHERE id=?",
                              (response.json()["id"],)).fetchone()[0]
            self.assertNotIn(base.TOKEN, saved)
        finally:
            c.close()

    def test_apply_uses_live_wire_format_and_persists_validation(self):
        plan = self.m.dns.preview("example.test")
        self.assertTrue(all(a["target"]["ttl"] == 60 for a in plan["actions"]))
        result = self.apply()
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["result"]["validation_status"], "passed")
        self.assertEqual(len(self.writes()), 4)
        mx = next(r for r in self.wire.records if r["type"] == "MX")
        self.assertEqual((mx["name"], mx["data"], mx["priority"]), ("", "mail.example.test.", 10))
        for _, _, _, kw in self.writes():
            self.assertNotIn("ttl", kw["body"])
            self.assertNotIn("comment", kw["body"])
        c = self.m.db()
        try:
            self.assertEqual(c.execute("SELECT count(*) FROM managed_dns_records").fetchone()[0], 4)
            self.assertEqual(c.execute("SELECT count(*) FROM domain_dns_operations WHERE status='confirmed'").fetchone()[0], 4)
        finally:
            c.close()
        before = len(self.writes())
        self.assertEqual(self.apply("dynv6-existing-fixture")["status"], "succeeded")
        self.assertEqual(len(self.writes()), before)

    def test_exact_inventory_reuses_only_identity_and_refreshes_primary_addresses(self):
        adapter = self.m.dns_adapter(self.m.domain("example.test"))
        self.wire.calls.clear()
        adapter.inventory("example.test")
        self.wire.zones[0]["ipv4address"] = "203.0.113.25"
        inventory = adapter.inventory("example.test")
        self.assertEqual(sum(c[2] == "/api/v2/zones" for c in self.wire.calls), 1)
        self.assertEqual(sum(c[2] == "/api/v2/zones/100" for c in self.wire.calls), 1)
        self.assertEqual(next(r["content"] for r in inventory["records"] if r["type"] == "A"), "203.0.113.25")

    def test_exact_inventory_reads_metadata_and_records_concurrently(self):
        import threading
        adapter = self.m.dns_adapter(self.m.domain("example.test"))
        adapter.inventory("example.test")
        request = self.wire.request
        entered = threading.Barrier(2)
        def observe(method, base_url, path, **kw):
            if path in {"/api/v2/zones/100", "/api/v2/zones/100/records"}:
                entered.wait(timeout=3)
            return request(method, base_url, path, **kw)
        with patch.object(self.wire, "request", side_effect=observe):
            adapter.inventory("example.test")

    def test_inherited_inventory_rediscovers_new_child_zone(self):
        adapter = Dynv6DNS(self.wire, {"api_token": base.TOKEN}, "child.example.test")
        self.assertEqual(adapter.inventory("child.example.test")["zone_id"], "100")
        self.wire.zones.append({"id": 101, "name": "child.example.test"})
        request = self.wire.request
        def observe(method, base_url, path, **kw):
            if path == "/api/v2/zones/101/records":
                return []
            return request(method, base_url, path, **kw)
        with patch.object(self.wire, "request", side_effect=observe):
            self.assertEqual(adapter.inventory("child.example.test")["zone_id"], "101")

    def test_primary_address_changes_still_block_before_first_write(self):
        request = self.wire.request
        def observe(method, base_url, path, **kw):
            if path == "/api/v2/zones/100":
                self.wire.zones[0]["ipv4address"] = "203.0.113.25"
            return request(method, base_url, path, **kw)
        with patch.object(self.wire, "request", side_effect=observe):
            result = self.apply()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "dns_changed_before_write")
        self.assertEqual(self.writes(), [])

    def test_changed_exact_zone_identity_is_rejected(self):
        adapter = self.m.dns_adapter(self.m.domain("example.test"))
        adapter.inventory("example.test")
        request = self.wire.request
        def observe(method, base_url, path, **kw):
            if path == "/api/v2/zones/100":
                return {"id": 100, "name": "another.test"}
            return request(method, base_url, path, **kw)
        with patch.object(self.wire, "request", side_effect=observe):
            with self.assertRaisesRegex(ProviderError, "dynv6_zone_changed"):
                adapter.inventory("example.test")
        self.assertEqual(self.writes(), [])

    def test_apply_preserves_live_record_reads_without_relisting_all_zones(self):
        self.wire.calls.clear()
        self.assertEqual(self.apply()["status"], "succeeded")
        # Preview and apply each discover once; all 8 per-record checks remain.
        self.assertEqual(sum(c[2] == "/api/v2/zones" for c in self.wire.calls), 2)
        self.assertEqual(sum(c[2] == "/api/v2/zones/100/records" and c[0] == "GET"
                             for c in self.wire.calls), 10)
        self.assertEqual(len(self.writes()), 4)

    def test_external_foreign_spf_blocks_before_any_write(self):
        self.wire.records.append({"id": 10, "zoneID": 100, "name": "", "type": "TXT", "data": "v=spf1 -all"})
        plan = self.m.dns.preview("example.test")
        self.assertFalse(plan["executable"])
        self.assertIn("foreign_record_conflict", [c["code"] for c in plan["conflicts"]])
        self.assertEqual(self.writes(), [])

    def test_owned_patch_preserves_unrelated_txt(self):
        self.assertEqual(self.apply()["status"], "succeeded")
        self.wire.records.append({"id": 30, "zoneID": 100, "name": "", "type": "TXT", "data": "provider-verify:keep"})
        row = self.m.domain("example.test")
        row["users"] = json.loads(row["users"])
        row["spf"] = "v=spf1 ip4:203.0.113.11 -all"
        self.m.save_domain(row)
        before = len(self.writes())
        result = self.apply("dynv6-update-fixture")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(len(self.writes()) - before, 1)
        method, _, _, kw = self.writes()[-1]
        self.assertEqual(method, "PATCH")
        self.assertNotIn("type", kw["body"])
        self.assertEqual(next(r for r in self.wire.records if r["id"] == 30)["data"], "provider-verify:keep")

    def test_timeout_never_replays_and_can_be_observed_without_adoption(self):
        self.wire.failure = "timeout"
        result = self.apply()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(len(self.writes()), 1)
        self.assertFalse(self.m.dns.preview("example.test")["executable"])
        self.assertFalse(self.m.run_once())
        observed = self.m.dns.reconcile_operation("example.test", result["result"]["operation_id"])
        self.assertEqual(observed["status"], "observed")
        self.assertFalse(observed["ownership_adopted"])
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.apply("dynv6-after-observe")["status"], "succeeded")
        self.assertEqual(len(self.writes()), 4)
        c = self.m.db()
        try:
            self.assertEqual(c.execute("SELECT count(*) FROM managed_dns_records").fetchone()[0], 3)
        finally:
            c.close()

    def test_rate_limit_fences_other_dynv6_writes(self):
        self.wire.failure = "rate"
        result = self.apply()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["result"]["provider_backoff"]["provider"], "dynv6")
        self.assertEqual(result["result"]["provider_backoff"]["retry_after_seconds"], 1200)
        queued = self.m.jobs.enqueue("dns_apply", "example.test", "dynv6-rate-followup", {"plan_id": "unused"})
        self.assertIsNone(self.m.jobs.take())
        self.assertEqual(self.m.jobs.get(queued["id"])["wait_reason"], "provider_cooldown")

    def test_binding_requires_accessible_zone_and_keeps_existing_binding(self):
        self.wire.zones = []
        other = self.m.add_dns_credential("dynv6", None, "other", {"api_token": base.TOKEN})
        response = self.case.client.post("/api/v1/mail-domains/example.test/dns-binding",
            headers=self.case.headers, json={"credential_ref": other["id"]})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["code"], "dynv6_zone_not_accessible")
        self.assertEqual(self.m.domain("example.test")["dns_credential_ref"], self.credential["id"])
        self.assertEqual(self.writes(), [])

    def test_inventory_expands_targets_and_includes_primary_addresses(self):
        self.wire.zones[0].update(ipv4address="203.0.113.10", ipv6prefix="2001:db8::1/64")
        self.wire.records = [
            {"id": 31, "zoneID": 100, "name": "*", "type": "MX", "data": "mx", "expandedData": "mx.example.test", "priority": 10},
            {"id": 32, "zoneID": 100, "name": "verify._domainkey", "type": "CNAME", "data": "brevo.example."},
        ]
        inventory = self.m.dns_adapter(self.m.domain("example.test")).inventory("example.test")
        records = scoped_inventory(inventory, "example.test", "dynv6")
        self.assertEqual(next(r for r in records if r["type"] == "MX")["name"], "*.example.test")
        self.assertEqual(next(r for r in records if r["type"] == "MX")["content"], "mx.example.test")
        self.assertEqual({r["type"] for r in records}, {"MX", "CNAME", "A", "AAAA"})

    def test_separate_txt_and_absolute_cname_wire_values(self):
        adapter = self.m.dns_adapter(self.m.domain("example.test"))
        adapter.inventory("example.test")
        for data in ("v=spf1 -all", "brevo-code:fixture"):
            adapter.write("100", {"type": "TXT", "name": "example.test", "content": data, "ttl": 60}, "unused")
        adapter.write("100", {"type": "CNAME", "name": "b._domainkey.example.test",
                              "content": "target.brevo.test", "ttl": 60}, "unused")
        self.assertEqual(len(self.wire.records), 3)
        self.assertEqual(self.wire.records[-1]["data"], "target.brevo.test.")
        self.assertEqual(self.wire.records[-1]["name"], "b._domainkey")
        self.assertEqual([r["data"] for r in self.wire.records[:2]], ["v=spf1 -all", "brevo-code:fixture"])

    def test_wildcard_plan_covers_existing_nodes_with_provider_ttl(self):
        row = self.m.domain("example.test")
        row["users"] = json.loads(row["users"])
        row.update(receive_subdomains=True, max_subdomain_depth=1)
        self.m.save_domain(row)
        self.wire.records = [{"id": 41, "zoneID": 100, "name": "app", "type": "A", "data": "203.0.113.10"}]
        plan = self.m.dns.preview("example.test")
        self.assertTrue(plan["executable"], plan["conflicts"])
        names = {a["target"]["name"] for a in plan["actions"] if a["target"]["type"] == "MX"}
        self.assertTrue({"*.example.test", "app.example.test"} <= names)
        self.assertNotIn("*.app.example.test", names)
        self.assertTrue(all(a["target"]["ttl"] == 60 for a in plan["actions"]))

    def test_multilevel_random_wildcard_blocks_before_writes(self):
        row = self.m.domain("example.test")
        row["users"] = json.loads(row["users"])
        row.update(receive_subdomains=True, max_subdomain_depth=6)
        self.m.save_domain(row)
        plan = self.m.dns.preview("example.test")
        self.assertFalse(plan["executable"])
        self.assertIn("dynv6_multilevel_wildcard_not_supported",
                      [item["code"] for item in plan["conflicts"]])
        with self.assertRaisesRegex(JobConflict, "conflicts"):
            self.m.dns.enqueue("example.test", plan["id"], "dynv6-depth-blocked")
        self.assertEqual(self.writes(), [])

    def test_live_domain_must_be_disabled_before_provider_switch(self):
        c = self.m.db()
        try:
            with c:
                c.execute("UPDATE mail_domains SET enabled=1,dns_provider='digitalplat' WHERE domain='example.test'")
        finally:
            c.close()
        before = len(self.wire.calls)
        with self.assertRaisesRegex(ValueError, "Disable this domain"):
            self.m.bind_dns_credential("example.test", self.credential["id"])
        self.assertEqual(len(self.wire.calls), before)
        self.assertEqual(self.m.domain("example.test")["dns_provider"], "digitalplat")

    def test_mismatched_zone_response_and_ambiguous_zones_fail_closed(self):
        self.wire.records = [{"id": 99, "zoneID": 101, "name": "", "type": "TXT", "data": "keep"}]
        with self.assertRaises(ProviderError):
            self.m.dns_adapter(self.m.domain("example.test")).inventory("example.test")
        self.wire.zones.append(copy.deepcopy(self.wire.zones[0]))
        with self.assertRaisesRegex(ProviderError, "ambiguous_dynv6_zone"):
            self.m.dns_adapter(self.m.domain("example.test")).inventory("example.test")


if __name__ == "__main__":
    unittest.main()
