#!/usr/bin/env python3
"""
Resilience policies for every outbound HTTP call the SOC makes.

Telegram, Groq and Cloudflare are still reached with plain urllib; this
module wraps those calls with retries, backoff, rate limiting and a
circuit breaker built on nopanic (https://github.com/dagdelenemre/nopanic),
so the scripts no longer hand-roll their own sleep loops.

Errors are never wrapped: callers still see the original urllib exception
(or nopanic.CircuitOpen while Telegram is known to be down), so their
existing try/except blocks keep working unchanged.
"""
import json
import math
import sys
import urllib.error
import urllib.request
from datetime import datetime

from nopanic import backoff, circuit_breaker, compose, rate_limit, retry, time_remaining


def _log(msg):
    print(f"[{datetime.now()}] {msg}", file=sys.stderr)


def _before_sleep(what):
    return lambda a: _log(
        f"{what} attempt {a.attempt} failed ({a.exception}). Retrying in {a.delay:.1f}s..."
    )


# ERROR CLASSIFICATION

def is_transient(exc):
    """
    Errors worth another attempt: network failures, timeouts, HTTP 429 and 5xx.
    Other 4xx (bad token, bad request, unknown model) are permanent.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    # URLError, TimeoutError and ConnectionError are all OSError subclasses
    return isinstance(exc, OSError)


def _is_timeout(exc):
    return isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)


def is_safe_to_resend(exc):
    """
    is_transient minus timeouts, for calls that are not idempotent: a
    sendMessage that timed out may already have been delivered.
    """
    return is_transient(exc) and not _is_timeout(exc)


def is_auth_error(exc):
    return isinstance(exc, urllib.error.HTTPError) and exc.code in (401, 403)


def _attach_retry_after(exc):
    """
    Copy a 429's Retry-After hint onto the exception as `retry_after`, which
    nopanic's retry honors as the minimum wait before the next attempt.
    Groq sends it as a header, Telegram inside the JSON error body.
    """
    if exc.code != 429:
        return
    hint = exc.headers.get("Retry-After") if exc.headers else None
    if hint is None:
        try:
            hint = json.loads(exc.read().decode()).get("parameters", {}).get("retry_after")
        except Exception:
            hint = None
    try:
        value = float(hint)
    except (TypeError, ValueError):
        return
    if math.isfinite(value) and value >= 0:
        exc.retry_after = value


# TRANSPORT

def _open(req, timeout):
    """
    One HTTP round trip. Inside a nopanic deadline the socket timeout is
    clamped to the time left, so a slow server cannot outlast the budget.
    """
    remaining = time_remaining()
    if remaining is not None:
        if remaining <= 0:
            raise TimeoutError("time budget exhausted")
        timeout = min(timeout, remaining)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        _attach_retry_after(exc)
        raise


def _open_json(req, timeout):
    return json.loads(_open(req, timeout).decode())


def _json_request(url, payload, headers=None):
    if payload is None:
        return urllib.request.Request(url, headers=headers or {})
    return urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8", **(headers or {})},
    )


# TELEGRAM

# One breaker for the whole process: once Telegram is clearly down, every
# caller fails fast for reset_timeout seconds instead of stacking retries.
telegram_breaker = circuit_breaker(
    failure_threshold=0.5,
    min_calls=5,
    window=60.0,
    reset_timeout=30.0,
    on=is_transient,
    name="telegram",
    on_state_change=lambda b, old, new: _log(f"Telegram circuit: {old} -> {new}"),
)

# Telegram allows roughly one message per second per chat; faster bursts get 429.
telegram_rate = rate_limit(1, per=1.0, burst=3, name="telegram")

_telegram_retry_idempotent = retry(
    attempts=3,
    on=is_transient,
    backoff=backoff.full_jitter(base=0.5, cap=10.0),
    retry_after_cap=30.0,
    before_sleep=_before_sleep("Telegram"),
)
_telegram_retry_send = retry(
    attempts=4,
    on=is_safe_to_resend,
    backoff=backoff.full_jitter(base=0.5, cap=10.0),
    retry_after_cap=30.0,
    before_sleep=_before_sleep("Telegram"),
)

_rate_limited_open_json = telegram_rate(_open_json)
_telegram_send = compose(_telegram_retry_send, telegram_breaker)(_rate_limited_open_json)
_telegram_edit = compose(_telegram_retry_idempotent, telegram_breaker)(_rate_limited_open_json)
_telegram_other = compose(_telegram_retry_idempotent, telegram_breaker)(_open_json)

_TELEGRAM_CALLS = {
    "sendMessage": _telegram_send,
    "editMessageText": _telegram_edit,
}


def telegram_api(token, method, payload=None, timeout=30):
    """
    Call a Telegram Bot API method and return the decoded JSON reply.
    Raises the original urllib error once retries are exhausted.
    """
    req = _json_request(f"https://api.telegram.org/bot{token}/{method}", payload)
    return _TELEGRAM_CALLS.get(method, _telegram_other)(req, timeout)


# GROQ

def _groq_worth_retrying(exc):
    """
    Retry the same model on network errors and 5xx. A 429 is retried only
    when the server asks for a short wait: Groq rate limits are per model,
    so on a longer one the caller is better off moving to the next model.
    """
    if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
        return getattr(exc, "retry_after", None) is not None and exc.retry_after <= 5
    return is_transient(exc)


_groq_post = retry(
    attempts=3,
    on=_groq_worth_retrying,
    backoff=backoff.full_jitter(base=1.0, cap=8.0),
    before_sleep=_before_sleep("Groq"),
)(_open_json)


def groq_chat(api_key, payload, timeout=30):
    """
    POST a chat completion to Groq and return the decoded JSON reply.
    Run it inside nopanic.deadline(...) to bound the total time.
    """
    req = _json_request(
        "https://api.groq.com/openai/v1/chat/completions",
        payload,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return _groq_post(req, timeout)


# PLAIN HTTP

_http_get = retry(
    attempts=4,
    on=is_transient,
    backoff=backoff.full_jitter(base=1.0, cap=15.0),
    before_sleep=_before_sleep("HTTP GET"),
)(_open)


def http_get_text(url, timeout=10):
    """GET a URL and return the body as text, retrying transient failures."""
    return _http_get(urllib.request.Request(url), timeout).decode()
