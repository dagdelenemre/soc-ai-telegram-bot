import importlib.util
import os
import re
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def analyzer():
    path = os.path.join(ROOT, "engine", "soc-log-analyzer.py")
    spec = importlib.util.spec_from_file_location("soc_log_analyzer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def nginx_line(ts, path="/"):
    return f'1.2.3.4 - - [{ts} +0000] "GET {path} HTTP/1.1" 200 612 "-" "curl/8.0"\n'


def local_from_utc(*args):
    return datetime(*args, tzinfo=timezone.utc).astimezone().replace(tzinfo=None)


# --- nginx access.log ---

def test_nginx_month_boundary_excludes_previous_month(analyzer):
    lines = [
        nginx_line("31/Oct/2026:23:50:00", "/old"),
        nginx_line("01/Nov/2026:00:04:59", "/before"),
        nginx_line("01/Nov/2026:00:05:00", "/at"),
        nginx_line("01/Nov/2026:00:06:00", "/after"),
    ]
    since = local_from_utc(2026, 11, 1, 0, 5, 0)
    out = analyzer.filter_since(lines, since, analyzer.parse_nginx_access_ts)
    assert "/old" not in out
    assert "/before" not in out
    assert "/at" in out and "/after" in out


def test_nginx_same_day_ordering(analyzer):
    lines = [
        nginx_line("16/Oct/2026:09:59:59", "/a"),
        nginx_line("16/Oct/2026:10:00:00", "/b"),
        nginx_line("16/Oct/2026:10:00:01", "/c"),
    ]
    since = local_from_utc(2026, 10, 16, 10, 0, 0)
    out = analyzer.filter_since(lines, since, analyzer.parse_nginx_access_ts)
    assert out == lines[1] + lines[2]


def test_nginx_year_boundary(analyzer):
    lines = [
        nginx_line("31/Dec/2026:23:59:00", "/old"),
        nginx_line("01/Jan/2027:00:01:00", "/new"),
    ]
    since = local_from_utc(2027, 1, 1, 0, 0, 0)
    out = analyzer.filter_since(lines, since, analyzer.parse_nginx_access_ts)
    assert "/old" not in out and "/new" in out


def test_nginx_offset_is_respected(analyzer):
    # 12:00 +0300 is 09:00 UTC
    line = '1.2.3.4 - - [16/Oct/2026:12:00:00 +0300] "GET / HTTP/1.1" 200 1 "-" "-"'
    assert analyzer.parse_nginx_access_ts(line) == local_from_utc(2026, 10, 16, 9, 0, 0)


# --- auth.log, classic syslog format ---

def test_syslog_single_digit_day(analyzer):
    now = datetime(2026, 11, 5, 10, 40)
    lines = [
        "Nov  4 23:59:59 web sshd[100]: Failed password for root from 1.2.3.4 port 22 ssh2\n",
        "Nov  5 10:29:59 web sshd[101]: Failed password for root from 1.2.3.5 port 22 ssh2\n",
        "Nov  5 10:30:00 web sshd[102]: Failed password for root from 1.2.3.6 port 22 ssh2\n",
        "Nov  5 10:35:00 web sshd[103]: Invalid user admin from 1.2.3.7 port 22\n",
    ]
    since = datetime(2026, 11, 5, 10, 30)
    out = analyzer.filter_since(lines, since, lambda l: analyzer.parse_syslog_ts(l, now))
    assert out == lines[2] + lines[3]


def test_syslog_month_boundary(analyzer):
    now = datetime(2026, 11, 1, 0, 10)
    lines = [
        "Oct 31 23:50:00 web sshd[1]: old\n",
        "Nov  1 00:06:00 web sshd[2]: new\n",
    ]
    since = datetime(2026, 11, 1, 0, 5)
    out = analyzer.filter_since(lines, since, lambda l: analyzer.parse_syslog_ts(l, now))
    assert out == lines[1]


def test_syslog_year_boundary(analyzer):
    now = datetime(2027, 1, 1, 0, 3)
    lines = [
        "Dec 31 23:58:00 web sshd[1]: old\n",
        "Jan  1 00:01:00 web sshd[2]: new\n",
    ]
    since = datetime(2026, 12, 31, 23, 59)
    assert analyzer.parse_syslog_ts(lines[0], now) == datetime(2026, 12, 31, 23, 58)
    out = analyzer.filter_since(lines, since, lambda l: analyzer.parse_syslog_ts(l, now))
    assert out == lines[1]


# --- auth.log, ISO 8601 format (newer Ubuntu) ---

def test_iso_auth_lines(analyzer):
    tz = timezone(timedelta(hours=3))
    lines = [
        "2026-11-05T10:29:59.999999+03:00 web sshd[1]: old\n",
        "2026-11-05T10:30:00.000123+03:00 web sshd[2]: at\n",
        "2026-11-05T10:31:00.5+03:00 web sshd[3]: after\n",
    ]
    since = datetime(2026, 11, 5, 10, 30, tzinfo=tz).astimezone().replace(tzinfo=None)
    out = analyzer.filter_since(lines, since, analyzer.parse_syslog_ts)
    assert out == lines[1] + lines[2]


def test_iso_auth_year_boundary(analyzer):
    lines = [
        "2026-12-31T23:59:00+00:00 web sshd[1]: old\n",
        "2027-01-01T00:01:00Z web sshd[2]: new\n",
    ]
    out = analyzer.filter_since(lines, local_from_utc(2027, 1, 1), analyzer.parse_syslog_ts)
    assert out == lines[1]


# --- lines without a timestamp ---

def test_untimestamped_lines_follow_previous_line(analyzer):
    now = datetime(2026, 11, 5, 12, 0)
    lines = [
        "garbage before any timestamp\n",
        "Nov  5 09:00:00 web sshd[1]: old\n",
        "  continuation of old\n",
        "Nov  5 11:00:00 web sshd[2]: new\n",
        "  continuation of new",
    ]
    out = analyzer.filter_since(lines, datetime(2026, 11, 5, 10, 0),
                                lambda l: analyzer.parse_syslog_ts(l, now))
    assert out == lines[3] + "  continuation of new\n"


# --- last-run state ---

def test_parse_last_run_isoformat(analyzer):
    assert analyzer.parse_last_run("2026-11-01T00:05:00.123456") == datetime(2026, 11, 1, 0, 5)


def test_parse_last_run_relative_default(analyzer):
    now = datetime(2026, 11, 1, 0, 5, 30)
    assert analyzer.parse_last_run("3 minutes ago", now) == datetime(2026, 11, 1, 0, 2, 30)


def test_parse_last_run_unreadable_falls_back_to_default_window(analyzer):
    now = datetime(2026, 11, 1, 0, 5, 30)
    assert analyzer.parse_last_run("garbage", now) == datetime(2026, 11, 1, 0, 2, 30)


# --- Cloudflare / own-IP exclusion ---
# grep -E and Python's re agree on these patterns (literals, classes, alternation).

CF_PATTERN = r"173\.245\.|104\.1[6-9]\."
CLIENT = '203.0.113.9 - - [01/Nov/2026:00:06:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.0"'
CLOUDFLARE = '104.16.1.1 - - [01/Nov/2026:00:06:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.0"'


def test_unset_server_ip_does_not_exclude_every_line(analyzer, monkeypatch):
    monkeypatch.setattr(analyzer, "SERVER_IP", "")
    pattern = analyzer.ip_exclusion(CF_PATTERN)
    assert not re.search(pattern, CLIENT)
    assert re.search(pattern, CLOUDFLARE)
    assert not re.search(f"SRC=({pattern})", "UFW BLOCK SRC=203.0.113.9 DST=10.0.0.1")


def test_server_ip_is_excluded_literally(analyzer, monkeypatch):
    monkeypatch.setattr(analyzer, "SERVER_IP", "198.51.100.7")
    pattern = analyzer.ip_exclusion(CF_PATTERN)
    assert re.search(pattern, "198.51.100.7 - - [01/Nov/2026:00:06:00 +0000] \"GET / HTTP/1.1\"")
    assert re.search(f"SRC=({pattern})", "UFW BLOCK SRC=198.51.100.7 DST=10.0.0.1")
    # Dots are literal: a different address must not match
    assert not re.search(pattern, "198x51x100x7 - - [01/Nov/2026:00:06:00 +0000]")
    assert not re.search(pattern, CLIENT)
