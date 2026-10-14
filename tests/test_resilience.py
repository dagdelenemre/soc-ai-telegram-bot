"""
Failure-scenario tests for the outbound HTTP calls (core/soc_resilience.py).

The network is replaced by a fake urlopen, and nopanic's testing.instant()
skips backoff waits, so the suite needs no tokens, no server and no
internet. Two tests run in real time on purpose (rate limit pacing and the
Groq time budget) and take a few seconds.

Run from the repository root:  pip install pytest && python -m pytest tests
"""
import email.message
import importlib
import importlib.util
import io
import json
import os
import sys
import time
import types
import urllib.error
import urllib.request

import pytest
from nopanic import deadline, testing

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GROQ_MODELS = [
    "moonshotai/kimi-k2-instruct",
    "llama-3.3-70b-versatile",
    "groq/compound",
    "groq/compound-mini",
    "llama-3.1-8b-instant",
]


# FAKE NETWORK

class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def ok(obj):
    return lambda: Resp(json.dumps(obj).encode())


def http_error(code, body=b"", headers=None):
    def make():
        msg = email.message.Message()
        for k, v in (headers or {}).items():
            msg[k] = v
        return urllib.error.HTTPError("https://example.invalid", code, "error", msg, io.BytesIO(body))
    return make


def refused():
    return urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))


def timed_out():
    return urllib.error.URLError(TimeoutError("timed out"))


TELEGRAM_OK = ok({"ok": True, "result": {"message_id": 7}})
GROQ_OK = ok({"choices": [{"message": {"content": "🔍 ANALYSIS RESULT\nCLEAN"}}]})


class FakeNet:
    """
    Stands in for urllib.request.urlopen. `script` maps a routing key to a
    list of outcomes (factories returning a response or an exception); the
    last outcome repeats. Requests are routed by URL substring, or by the
    Groq model name in the JSON body.
    """

    def __init__(self, script):
        self.script = {k: list(v) for k, v in script.items()}
        self.calls = []

    def _key(self, req):
        if "groq.com" in req.full_url:
            return json.loads(req.data)["model"]
        for key in self.script:
            if key in req.full_url:
                return key
        raise AssertionError(f"unexpected request to {req.full_url}")

    def __call__(self, req, timeout=None):
        key = self._key(req)
        self.calls.append((key, req, timeout))
        outcomes = self.script.get(key, [GROQ_OK])
        out = (outcomes.pop(0) if len(outcomes) > 1 else outcomes[0])()
        if isinstance(out, BaseException):
            raise out
        return out

    def count(self, key):
        return sum(1 for k, _, _ in self.calls if k == key)


# FIXTURES

def _load_script(rel_path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def soc(monkeypatch):
    """
    Fresh policy state for every test: soc_resilience is reloaded (new
    breaker, empty rate limit bucket) before the scripts import it.
    """
    import core.soc_resilience
    resilience = importlib.reload(core.soc_resilience)

    notifier = _load_script("bot/soc-notifier.py", "soc_notifier")
    monkeypatch.setattr(notifier, "save_pending", lambda *a, **k: 42)

    analyzer = _load_script("engine/soc-log-analyzer.py", "soc_log_analyzer")
    monkeypatch.setattr(analyzer, "run_cmd", lambda cmd: "")

    return types.SimpleNamespace(
        resilience=resilience,
        notifier=notifier,
        analyzer=analyzer,
        listener=_load_script("bot/soc-bot-listener.py", "soc_bot_listener"),
        daily=_load_script("engine/soc-daily-report.py", "soc_daily_report"),
        cloudflare=_load_script("scripts/update-cloudflare-ips.py", "update_cloudflare_ips"),
    )


@pytest.fixture
def network(monkeypatch):
    def install(script):
        net = FakeNet(script)
        monkeypatch.setattr(urllib.request, "urlopen", net)
        return net
    return install


# TELEGRAM

def test_telegram_429_waits_for_retry_after_then_delivers(soc, network):
    body = json.dumps({"ok": False, "parameters": {"retry_after": 5}}).encode()
    net = network({"sendMessage": [http_error(429, body), TELEGRAM_OK]})

    with testing.instant() as sleeps:
        result = soc.notifier.send_message("TOKEN", 1, "alert")

    assert result["ok"]
    assert net.count("sendMessage") == 2
    assert max(sleeps) >= 5


def test_send_message_is_not_resent_after_a_timeout(soc, network):
    # A timed-out sendMessage may already have been delivered
    net = network({"sendMessage": [timed_out]})

    with testing.instant():
        assert soc.notifier.send_message("TOKEN", 1, "alert") is None

    assert net.count("sendMessage") == 1


def test_send_message_is_retried_when_the_connection_fails(soc, network):
    net = network({"sendMessage": [refused, refused, TELEGRAM_OK]})

    with testing.instant():
        assert soc.notifier.send_message("TOKEN", 1, "alert")["ok"]

    assert net.count("sendMessage") == 3


def test_permanent_client_errors_are_not_retried(soc, network):
    net = network({"sendMessage": [http_error(400)]})

    with testing.instant():
        assert soc.notifier.send_message("TOKEN", 1, "alert") is None

    assert net.count("sendMessage") == 1


def test_edit_message_is_retried_after_a_timeout(soc, network):
    # editMessageText is idempotent, so a timeout is safe to retry
    net = network({"editMessageText": [timed_out, TELEGRAM_OK]})

    with testing.instant():
        soc.listener.edit_message("TOKEN", 1, 7, "done")

    assert net.count("editMessageText") == 2


def test_outage_opens_the_circuit_and_bounds_requests(soc, network):
    net = network({"sendMessage": [refused]})
    threats = [{"severity": "HIGH", "category": f"cat{i}", "description": "d", "action": "check"}
               for i in range(6)]

    with testing.instant(), testing.capture_events("breaker.") as events:
        soc.notifier.process_threats("TOKEN", 1, threats, "")

    assert soc.resilience.telegram_breaker.state == "open"
    # Without the breaker: 6 alerts x 4 attempts = 24 requests
    assert net.count("sendMessage") == 5
    assert sum(e.kind == "breaker.rejected" for e in events) == 5


def test_notifier_still_attaches_approve_reject_buttons(soc, network):
    net = network({"sendMessage": [TELEGRAM_OK], "editMessageText": [TELEGRAM_OK]})
    threat = {"severity": "CRITICAL", "category": "SQL Injection", "description": "d", "action": "ban"}

    with testing.instant():
        soc.notifier.process_threats("TOKEN", 1, [threat], "203.0.113.9 - - GET /?q=UNION SELECT")

    assert net.count("sendMessage") == 1
    edit = json.loads(next(req for key, req, _ in net.calls if key == "editMessageText").data)
    buttons = edit["reply_markup"]["inline_keyboard"][0]
    assert [b["callback_data"] for b in buttons] == ["soc_APPROVE_42", "soc_REJECT_42"]
    assert "nginx-ban-ip.py 203.0.113.9" in edit["text"]


def test_listener_api_call_keeps_its_return_contract(soc, network):
    updates = {"ok": True, "result": []}
    network({"getUpdates": [ok(updates)], "sendMessage": [http_error(403)]})

    with testing.instant():
        assert soc.listener.api_call("TOKEN", "getUpdates", {"offset": 0, "timeout": 25}) == updates
        assert soc.listener.api_call("TOKEN", "sendMessage", {"chat_id": 1, "text": "x"}) is None


def test_listener_sends_nothing_while_the_circuit_is_open(soc, network):
    net = network({"getUpdates": [ok({"ok": True, "result": []})]})
    soc.resilience.telegram_breaker.force_open()

    assert soc.listener.api_call("TOKEN", "getUpdates", {"offset": 0}) is None
    assert net.calls == []


def test_daily_report_is_retried_on_5xx(soc, network):
    net = network({"sendMessage": [http_error(502), TELEGRAM_OK]})

    with testing.instant():
        soc.daily.send_telegram("TOKEN", 1, "report")

    assert net.count("sendMessage") == 2


def test_message_bursts_are_paced_to_one_per_second(soc, network):
    # Real time: burst of 3, then ~1 message per second
    network({"sendMessage": [TELEGRAM_OK]})

    started = time.monotonic()
    for _ in range(6):
        soc.notifier.send_message("TOKEN", 1, "alert")
    elapsed = time.monotonic() - started

    assert 2.5 < elapsed < 4.0


# CLOUDFLARE

def test_cloudflare_ip_sync_recovers_from_transient_errors(soc, network):
    network({
        "ips-v4": [refused, http_error(503), lambda: Resp(b"173.245.48.0/20\n103.21.244.0/22")],
        "ips-v6": [lambda: Resp(b"2400:cb00::/32")],
    })

    with testing.instant():
        ips = soc.cloudflare.fetch_ips()

    assert ips == ["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"]


# GROQ

def test_groq_long_429_moves_to_the_next_model_at_once(soc, network):
    net = network({
        GROQ_MODELS[0]: [http_error(429, headers={"Retry-After": "30"})],
        GROQ_MODELS[1]: [http_error(503), GROQ_OK],
    })

    with testing.instant() as sleeps:
        result = soc.analyzer.analyze_with_groq("logs")

    assert result.startswith("ANALYSIS RESULT")
    # Rate limits are per model: no 30s wait, model 2 is retried after its 503
    assert [key for key, _, _ in net.calls] == [GROQ_MODELS[0], GROQ_MODELS[1], GROQ_MODELS[1]]
    assert max(sleeps) < 30


def test_groq_short_429_is_retried_on_the_same_model(soc, network):
    net = network({GROQ_MODELS[0]: [http_error(429, headers={"Retry-After": "2"}), GROQ_OK]})

    with testing.instant() as sleeps:
        assert soc.analyzer.analyze_with_groq("logs").startswith("ANALYSIS RESULT")

    assert net.count(GROQ_MODELS[0]) == 2
    assert max(sleeps) >= 2


def test_groq_rejected_api_key_stops_after_one_request(soc, network):
    net = network({model: [http_error(401)] for model in GROQ_MODELS})

    with testing.instant() as sleeps:
        assert soc.analyzer.analyze_with_groq("logs") == "ANALYSIS_FAILED"

    assert len(net.calls) == 1
    assert sleeps == []


def test_groq_analysis_never_outlasts_its_time_budget(soc, monkeypatch):
    # Real time: every request blocks for its whole timeout. A 2s outer
    # deadline shortens the 75s production budget (nested deadlines only shorten).
    def hang(req, timeout=None):
        time.sleep(timeout)
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", hang)

    started = time.monotonic()
    with deadline(2):
        result = soc.analyzer.analyze_with_groq("logs")
    elapsed = time.monotonic() - started

    assert result == "ANALYSIS_FAILED"
    assert elapsed < 2.5
