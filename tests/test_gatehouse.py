import asyncio
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from gatehouse import Masker, load
from gatehouse.policy import Replays
from gatehouse.server import build

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "examples" / "igaming"


def fresh_backend():
    spec = importlib.util.spec_from_file_location("backend", EXAMPLE / "backend.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Decisions(unittest.TestCase):
    gate = load(EXAMPLE / "gatehouse.yaml")

    def action(self, tool, args, profile="support-write"):
        d = self.gate.decide(profile, tool, args)
        return d.action, d.rule

    def test_bank_account_changes_always_go_to_a_human(self):
        self.assertEqual(self.action("update_bank_account", {"iban": "x"}),
                         ("handoff", "bank-account-changes-go-to-a-human"))

    def test_bonus_threshold(self):
        self.assertEqual(self.action("apply_bonus", {"amount_eur": 50})[0], "allow")
        self.assertEqual(self.action("apply_bonus", {"amount_eur": 50.01})[0], "handoff")

    def test_missing_resolution_is_denied_present_is_allowed(self):
        self.assertEqual(self.action("close_ticket", {"ticket_id": "T"})[0], "deny")
        self.assertEqual(self.action("close_ticket", {"ticket_id": "T", "resolution": "paid"})[0], "allow")

    def test_iban_in_a_public_comment_only(self):
        body = "Your refund goes to ES91 2100 0418 4502 0005 1332"
        self.assertEqual(self.action("add_ticket_comment", {"body": body, "public": True})[0], "deny")
        self.assertEqual(self.action("add_ticket_comment", {"body": body, "public": False})[0], "allow")

    def test_an_argument_a_rule_cannot_read_is_denied_not_crashed(self):
        self.assertEqual(self.action("apply_bonus", {"amount_eur": "lots"})[0], "deny")

    def test_profiles_are_the_permission(self):
        self.assertEqual(self.action("apply_bonus", {"amount_eur": 1}, "support-read"), ("deny", "profile"))
        self.assertEqual(self.action("export_player_data", {}), ("deny", "profile"))

    def test_handoff_payload_tells_the_agent_what_to_do(self):
        err = self.gate.decide("support-write", "set_self_exclusion", {}).as_error()
        self.assertEqual(err["error"], "needs_human")
        self.assertIn("initiate_human_handoff", err["next"])


class HardenedAgainstBypass(unittest.TestCase):
    """Regression tests from the security review: a rule must read arguments the way the upstream
    will execute them, and anything it cannot read must fail closed."""
    gate = load(EXAMPLE / "gatehouse.yaml")

    def action(self, tool, args):
        return self.gate.decide("support-write", tool, args).action

    def test_nan_and_infinity_do_not_slip_under_a_threshold(self):
        for amount in ("nan", float("nan"), "inf", float("inf"), True):
            self.assertEqual(self.action("apply_bonus", {"amount_eur": amount}), "deny", amount)

    def test_negative_and_zero_bonuses_are_refused(self):
        self.assertEqual(self.action("apply_bonus", {"amount_eur": -100}), "deny")
        self.assertEqual(self.action("apply_bonus", {"amount_eur": "0"}), "deny")

    def test_numbers_as_strings_are_read_as_numbers(self):
        self.assertEqual(self.action("apply_bonus", {"amount_eur": "120"}), "handoff")

    def test_a_string_true_is_true(self):
        body = "refund to ES91 2100 0418 4502 0005 1332"
        for public in ("true", "True", "1", "yes", 1):
            self.assertEqual(self.action("add_ticket_comment", {"body": body, "public": public}), "deny", public)

    def test_whitespace_is_missing(self):
        self.assertEqual(self.action("close_ticket", {"ticket_id": "T", "resolution": "   "}), "deny")

    def test_field_names_match_regardless_of_spelling(self):
        m = Masker({"iban": "last4", "date_of_birth": "drop"}, [])
        self.assertEqual(m({"IBAN": "ES9121000418450200051332", "dateOfBirth": "1991", "Date-Of-Birth": "1991"}),
                         {"IBAN": "****1332"})

    def test_refuses_to_start_when_the_declared_key_is_missing(self):
        env = {k: v for k, v in os.environ.items() if k != "MCP_API_KEY"}
        env["PYTHONPATH"] = str(ROOT)
        r = subprocess.run([sys.executable, "-m", "gatehouse", str(EXAMPLE / "gatehouse.yaml"),
                            "--profile", "support-write", "--port", str(free_port())],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Refusing to serve unauthenticated", r.stderr)


class Masking(unittest.TestCase):
    m = Masker({"iban": "last4", "email": "domain", "date_of_birth": "drop"}, ["iban", "card", "email", "phone"])

    def test_named_fields_anywhere_in_the_tree(self):
        out = self.m({"players": [{"iban": "ES91 2100 0418 4502 0005 1332", "date_of_birth": "1991",
                                   "email": "a.b@example.com", "name": "Lucía"}]})
        self.assertEqual(out, {"players": [{"iban": "****1332", "email": "***@example.com", "name": "Lucía"}]})

    def test_pii_inside_free_text(self):
        s = self.m("send to PT50 0002 0123 1234 5678 9015 4, call +351 912 345 678, mail joao@x.pt")
        self.assertNotIn("0123", s)
        self.assertNotIn("912 345", s)
        self.assertIn("***@x.pt", s)

    def test_only_real_card_numbers_are_masked(self):
        self.assertEqual(self.m("card 4111 1111 1111 1111"), "card ****1111")    # passes Luhn
        self.assertEqual(self.m("order 1234 5678 9012 3456"), "order 1234 5678 9012 3456")

    def test_ordinary_text_and_amounts_survive(self):
        s = "Withdrawal of 40 EUR pending 3 days, ticket T-501, balance 42.50"
        self.assertEqual(self.m(s), s)

    def test_json_text_blocks_are_masked_by_field(self):
        self.assertEqual(json.loads(self.m.text('{"iban": "ES9121000418450200051332"}')), {"iban": "****1332"})


class Idempotency(unittest.TestCase):
    def test_window(self):
        r = Replays(["apply_bonus"], window_seconds=600)
        k = r.key("apply_bonus", {"amount_eur": 10})
        self.assertIsNone(r.key("get_player", {}))
        r.put(k, "first")
        self.assertEqual(r.get(k), "first")
        self.assertNotEqual(k, r.key("apply_bonus", {"amount_eur": 11}))
        r.window = 0
        self.assertIsNone(r.get(k))


class EndToEnd(unittest.TestCase):
    """Through a real fastmcp proxy, in memory."""

    def run_calls(self, calls, profile="support-write"):
        backend = fresh_backend()
        gate = load(EXAMPLE / "gatehouse.yaml")
        gate.audit_log = str(Path(tempfile.mkdtemp()) / "audit.jsonl")

        async def go():
            async with Client(build(gate, profile, upstream=backend.mcp)) as c:
                tools = sorted(t.name for t in await c.list_tools())
                results = [await c.call_tool(t, a, raise_on_error=False) for t, a in calls]
                return tools, results

        tools, results = asyncio.run(go())
        log = Path(gate.audit_log)
        audit = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return backend, tools, [r.structured_content for r in results], audit

    def test_read_profile_cannot_see_writes(self):
        _, tools, _, _ = self.run_calls([], profile="support-read")
        self.assertEqual(tools, ["get_player", "get_ticket", "list_transactions"])

    def test_the_model_never_sees_raw_pii(self):
        _, _, (player, ticket), _ = self.run_calls([("get_player", {"player_id": "P-1001"}),
                                                    ("get_ticket", {"ticket_id": "T-501"})])
        self.assertEqual(player["iban"], "****1332")
        self.assertNotIn("date_of_birth", player)
        self.assertNotIn("2100 0418", ticket["description"])

    def test_handoff_leaves_the_upstream_untouched(self):
        backend, _, (res,), audit = self.run_calls(
            [("update_bank_account", {"player_id": "P-1001", "iban": "ES76 2077 0024 0031 0257 5766"})])
        self.assertEqual(res["error"], "needs_human")
        self.assertEqual(backend.PLAYERS["P-1001"]["iban"], "ES91 2100 0418 4502 0005 1332")
        self.assertEqual(audit[0]["args"]["iban"], "****5766")       # no raw IBAN in the audit log

    def test_shadow_mode_records_the_verdict_but_runs_the_call_masked(self):
        backend = fresh_backend()
        gate = load(EXAMPLE / "gatehouse.yaml")
        gate.shadow, gate.audit_log = True, str(Path(tempfile.mkdtemp()) / "audit.jsonl")

        async def go():
            async with Client(build(gate, "support-write", upstream=backend.mcp)) as c:
                return await c.call_tool("update_bank_account", {"player_id": "P-1001", "iban": "DE89 3704 0044 0532 0130 00"})

        res = asyncio.run(go())
        line = json.loads(Path(gate.audit_log).read_text())
        self.assertEqual((line["decision"], line["enforced"]), ("handoff", False))
        self.assertEqual(res.structured_content["status"], "UPDATED")            # it ran
        self.assertEqual(res.structured_content["iban"], "****3000")             # still masked

    def test_shadow_mode_never_opens_the_profile(self):
        backend = fresh_backend()
        gate = load(EXAMPLE / "gatehouse.yaml")
        gate.shadow = True

        async def go():
            async with Client(build(gate, "support-read", upstream=backend.mcp)) as c:
                return await c.call_tool("apply_bonus", {"player_id": "P-1001", "amount_eur": 10, "reason": "x"},
                                         raise_on_error=False)

        res = asyncio.run(go())
        self.assertEqual(res.structured_content["rule"], "profile")
        self.assertEqual(backend.PLAYERS["P-1001"]["balance_eur"], 42.5)

    def test_upstream_resources_and_prompts_are_not_proxied(self):
        from fastmcp import FastMCP
        up = FastMCP("leaky")

        @up.resource("players://{player_id}")
        def player(player_id: str) -> str:
            return "IBAN ES91 2100 0418 4502 0005 1332"

        @up.resource("config://secrets")
        def secrets() -> str:
            return "api_key=live-123"

        @up.prompt
        def internal_notes() -> str:
            return "internal escalation playbook"

        gate = load(EXAMPLE / "gatehouse.yaml")

        async def go():
            async with Client(build(gate, "support-write", upstream=up)) as c:
                listed = (await c.list_resources(), await c.list_resource_templates(), await c.list_prompts())
                with self.assertRaises(Exception):
                    await c.read_resource("config://secrets")
                with self.assertRaises(Exception):
                    await c.read_resource("players://P-1001")
                with self.assertRaises(Exception):
                    await c.get_prompt("internal_notes")
                return listed

        self.assertEqual(asyncio.run(go()), ([], [], []))

    def test_content_that_cannot_be_inspected_is_withheld(self):
        from fastmcp import FastMCP
        from fastmcp.utilities.types import Image
        up = FastMCP("kyc")

        @up.tool
        def get_id_document(player_id: str) -> Image:
            return Image(data=b"\x89PNG fake passport scan", format="png")

        gate = load(EXAMPLE / "gatehouse.yaml")
        gate.profiles["support-write"].append("get_id_document")

        async def go():
            async with Client(build(gate, "support-write", upstream=up)) as c:
                return await c.call_tool("get_id_document", {"player_id": "P-1001"})

        res = asyncio.run(go())
        self.assertEqual([b.type for b in res.content], ["text"])
        self.assertIn("withheld", res.content[0].text)

    def test_a_retried_bonus_is_paid_once(self):
        call = ("apply_bonus", {"player_id": "P-1001", "amount_eur": 10, "reason": "slow"})
        backend, _, (a, b), audit = self.run_calls([call, call])
        self.assertEqual(a["bonus_id"], b["bonus_id"])
        self.assertEqual(backend.PLAYERS["P-1001"]["balance_eur"], 52.5)
        self.assertEqual([x["decision"] for x in audit], ["allow", "replayed"])


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(port):
    for _ in range(100):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(port)


class OverHttp(unittest.TestCase):
    """The way an InteractiveAI agent reaches it: streamable-http, Bearer key from the manifest."""

    def test_bearer_key_is_required_and_the_gate_still_applies(self):
        up, gh = free_port(), free_port()
        cfg = Path(tempfile.mkdtemp()) / "gatehouse.yaml"
        cfg.write_text((EXAMPLE / "gatehouse.yaml").read_text()
                       .replace("upstream: backend.py", f"upstream: http://127.0.0.1:{up}/mcp"))
        env = {**os.environ, "MCP_API_KEY": "test-key", "PYTHONPATH": str(ROOT)}
        backend = subprocess.Popen([sys.executable, "-c",
                                    f"import runpy,sys; sys.argv=['b']; m=runpy.run_path('{EXAMPLE / 'backend.py'}');"
                                    f"m['mcp'].run(transport='streamable-http', host='127.0.0.1', port={up})"],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        gate = subprocess.Popen([sys.executable, "-m", "gatehouse", str(cfg), "--profile", "support-write",
                                 "--host", "127.0.0.1", "--port", str(gh)],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for(up), wait_for(gh)
            url = f"http://127.0.0.1:{gh}/mcp"

            async def call(headers):
                async with Client(StreamableHttpTransport(url, headers=headers)) as c:
                    return await c.call_tool("update_bank_account", {"player_id": "P-1001", "iban": "x"},
                                             raise_on_error=False)

            with self.assertRaises(Exception):
                asyncio.run(call({}))
            res = asyncio.run(call({"Authorization": "Bearer test-key"}))
            self.assertEqual(res.structured_content["rule"], "bank-account-changes-go-to-a-human")
        finally:
            backend.terminate(), gate.terminate()


if __name__ == "__main__":
    unittest.main()
