"""Tests for ``eopx.server.rate_limit``.

Exercises:
  * env-driven configuration (override + disable)
  * sliding-window arithmetic at boundary values (0, 1, full, burst)
  * 429 emission with structured body and Retry-After header
  * fail-open on misconfigured env (invalid rate spec)
  * keyed-by-IP isolation
"""

from __future__ import annotations

import importlib

import pytest

flask = pytest.importorskip("flask")


@pytest.fixture
def rate_limit_module(monkeypatch):
    """Reload the module after env mutations so module-level state resets."""
    # Ensure no env from a previous test pollutes us.
    for k in (
        "ESOPTRON_RATE_LIMIT_DEFAULT",
        "ESOPTRON_RATE_LIMIT_HEAVY",
        "ESOPTRON_RATE_LIMIT_ANCHOR",
        "ESOPTRON_RATE_LIMIT_DISABLE",
    ):
        monkeypatch.delenv(k, raising=False)
    import eopx.server.rate_limit as rl
    importlib.reload(rl)
    return rl


def _make_app(rl):
    app = flask.Flask(__name__)

    @app.route("/", methods=["GET"])
    @rl.rate_limit("default")
    def index():
        return "ok"

    @app.route("/heavy", methods=["GET"])
    @rl.rate_limit("heavy")
    def heavy():
        return "ok"

    return app


# ---------------------------------------------------------------------------
# Rate-spec parsing
# ---------------------------------------------------------------------------

class TestParseRate:
    def test_basic(self, rate_limit_module):
        assert rate_limit_module._parse_rate("60/minute") == (60, 60)

    def test_plural_unit_accepted(self, rate_limit_module):
        # "60/minutes" should also parse — the rstrip('s') normalisation.
        assert rate_limit_module._parse_rate("60/minutes") == (60, 60)

    def test_seconds_hour_day(self, rate_limit_module):
        rl = rate_limit_module
        assert rl._parse_rate("5/second") == (5, 1)
        assert rl._parse_rate("100/hour") == (100, 3600)
        assert rl._parse_rate("1000/day") == (1000, 86400)

    def test_whitespace_tolerated(self, rate_limit_module):
        assert rate_limit_module._parse_rate("  30 / minute  ") == (30, 60)

    @pytest.mark.parametrize("bad", [
        "60/fortnight", "abc/minute", "0/minute", "-5/minute", "60",
    ])
    def test_invalid_specs_rejected(self, rate_limit_module, bad):
        with pytest.raises(ValueError):
            rate_limit_module._parse_rate(bad)


# ---------------------------------------------------------------------------
# Env overrides + disable switch
# ---------------------------------------------------------------------------

class TestEnvConfig:
    def test_override_default_via_env(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DEFAULT", "3/minute")
        importlib.reload(rate_limit_module)
        assert rate_limit_module._rate_for("default") == (3, 60)

    def test_override_heavy_via_env(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_HEAVY", "2/second")
        importlib.reload(rate_limit_module)
        assert rate_limit_module._rate_for("heavy") == (2, 1)

    def test_disable_flag(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DISABLE", "1")
        importlib.reload(rate_limit_module)
        assert rate_limit_module._is_disabled() is True
        monkeypatch.delenv("ESOPTRON_RATE_LIMIT_DISABLE")
        assert rate_limit_module._is_disabled() is False

    def test_disable_skips_limiter(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DISABLE", "1")
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DEFAULT", "1/minute")
        importlib.reload(rate_limit_module)
        app = _make_app(rate_limit_module)
        client = app.test_client()
        for _ in range(5):
            r = client.get("/")
            assert r.status_code == 200


# ---------------------------------------------------------------------------
# Sliding window behaviour
# ---------------------------------------------------------------------------

class TestSlidingWindow:
    def test_allows_up_to_limit(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DEFAULT", "3/minute")
        importlib.reload(rate_limit_module)
        app = _make_app(rate_limit_module)
        client = app.test_client()
        for i in range(3):
            r = client.get("/")
            assert r.status_code == 200, f"request {i+1} should pass"

    def test_rejects_burst_beyond_limit(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DEFAULT", "2/minute")
        importlib.reload(rate_limit_module)
        app = _make_app(rate_limit_module)
        client = app.test_client()
        assert client.get("/").status_code == 200
        assert client.get("/").status_code == 200
        r = client.get("/")
        assert r.status_code == 429
        body = r.get_json()
        assert body["error"] == "rate_limit_exceeded"
        assert body["bucket"] == "default"
        assert body["limit"] == "2/60s"
        assert "retry_after" in body
        assert "Retry-After" in r.headers
        # Retry-After must be a positive integer string.
        retry_int = int(r.headers["Retry-After"])
        assert retry_int >= 1

    def test_different_buckets_are_independent(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DEFAULT", "1/minute")
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_HEAVY", "1/minute")
        importlib.reload(rate_limit_module)
        app = _make_app(rate_limit_module)
        client = app.test_client()
        # Hit /
        assert client.get("/").status_code == 200
        # Same IP, different bucket → still allowed.
        assert client.get("/heavy").status_code == 200
        # Both now at limit.
        assert client.get("/").status_code == 429
        assert client.get("/heavy").status_code == 429

    def test_different_ips_are_independent(self, rate_limit_module, monkeypatch):
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DEFAULT", "1/minute")
        importlib.reload(rate_limit_module)
        app = _make_app(rate_limit_module)
        client = app.test_client()
        # IP A
        assert client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}).status_code == 200
        # IP B — independent counter.
        assert client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.2"}).status_code == 200
        # IP A at limit.
        assert client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}).status_code == 429
        # IP B still OK once more? No: B used its slot too.
        assert client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.2"}).status_code == 429


# ---------------------------------------------------------------------------
# Fail-open on misconfiguration
# ---------------------------------------------------------------------------

class TestFailOpen:
    def test_invalid_env_does_not_500(self, rate_limit_module, monkeypatch):
        """A typo in the env should not break the service; requests pass."""
        monkeypatch.setenv("ESOPTRON_RATE_LIMIT_DEFAULT", "not-a-rate")
        importlib.reload(rate_limit_module)
        app = _make_app(rate_limit_module)
        client = app.test_client()
        for _ in range(10):
            r = client.get("/")
            assert r.status_code == 200


# ---------------------------------------------------------------------------
# Internal _SlidingWindow datastructure
# ---------------------------------------------------------------------------

class TestSlidingWindowDataStructure:
    def test_zero_then_one(self, rate_limit_module):
        sw = rate_limit_module._SlidingWindow()
        assert sw.check("b", "k", limit=1, window=60) is None
        # Second hit must be denied with a retry-after > 0.
        retry = sw.check("b", "k", limit=1, window=60)
        assert retry is not None and retry > 0

    def test_independent_keys(self, rate_limit_module):
        sw = rate_limit_module._SlidingWindow()
        assert sw.check("b", "ip-a", 1, 60) is None
        assert sw.check("b", "ip-b", 1, 60) is None
        # Both keys at limit; either further hit is denied.
        assert sw.check("b", "ip-a", 1, 60) is not None
        assert sw.check("b", "ip-b", 1, 60) is not None

    def test_window_eviction(self, rate_limit_module, monkeypatch):
        """Old timestamps past the window are evicted, freeing capacity."""
        sw = rate_limit_module._SlidingWindow()
        import eopx.server.rate_limit as rl_mod

        # Fake monotonic that returns the desired sequence.
        timeline = [0.0, 0.5, 1000.0]   # 1st two within 1s, 3rd way past 1s
        idx = {"i": 0}

        def fake_monotonic():
            v = timeline[idx["i"]]
            idx["i"] += 1
            return v

        monkeypatch.setattr(rl_mod.time, "monotonic", fake_monotonic)

        # window=1s, limit=2 → first two pass; third has 0 still in the window
        # but timeline jumps 1000s, so previous entries evicted.
        assert sw.check("b", "k", 2, 1) is None    # t=0.0
        assert sw.check("b", "k", 2, 1) is None    # t=0.5
        assert sw.check("b", "k", 2, 1) is None    # t=1000.0 → old ones evicted
