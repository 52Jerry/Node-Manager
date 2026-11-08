import concurrent.futures
import logging
import sys
from unittest.mock import Mock, PropertyMock, patch

from background_logging import PollingLogFilter, configure_background_logging


def record(message="traffic collection failed", name="monitor.traffic", args=(), exc_info=None):
    return logging.LogRecord(name, logging.WARNING, __file__, 1, message, args, exc_info)


def test_duplicate_poll_errors_are_counted_without_retaining_payloads():
    now = [0.0]
    limiter = PollingLogFilter(clock=lambda: now[0])
    assert limiter.filter(record())
    for _ in range(10000):
        assert not limiter.filter(record())
    now[0] = 60
    event = record()
    assert limiter.filter(event)
    assert "suppressed: 10000" in event.getMessage()
    assert len(limiter._windows) == 1
    assert limiter._windows[("monitor.traffic", "traffic collection failed", logging.WARNING)] == (60, 0)


def test_auth_mutation_and_unknown_errors_are_never_suppressed():
    limiter = PollingLogFilter()
    for _ in range(100):
        for event in (record("authentication failed"), record("failed to apply user policy"),
                      record("traffic collection failed", name="security"), record({"arbitrary": True})):
            assert limiter.filter(event)
    assert not limiter._windows


def test_exception_and_lazy_formatting_survive_periodic_report():
    now = [0.0]
    limiter = PollingLogFilter(clock=lambda: now[0])
    try:
        raise RuntimeError("diagnostic")
    except RuntimeError:
        trace = sys.exc_info()
    first = record("Sing-box connection metrics are not available: %s", "singbox.api", ("Timeout",), trace)
    assert limiter.filter(first) and first.exc_info is trace
    assert not limiter.filter(record(first.msg, first.name, ("Timeout",), trace))
    now[0] = 61
    periodic = record(first.msg, first.name, ("Timeout",), trace)
    assert limiter.filter(periodic)
    assert "Timeout" in periodic.getMessage() and "suppressed: 1" in periodic.getMessage()
    assert periodic.exc_info is trace


def test_parallel_failures_emit_one_initial_record():
    limiter = PollingLogFilter(clock=lambda: 0)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(lambda _: limiter.filter(record()), range(1000))) == 1


def test_setup_is_idempotent_and_http_success_is_quiet():
    configure_background_logging()
    configure_background_logging()
    logger = logging.getLogger("monitor.traffic")
    assert sum(isinstance(item, PollingLogFilter) for item in logger.filters) == 1
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING


def test_api_error_does_not_read_or_format_full_response_body():
    from singbox.api import SingboxAPI
    api = SingboxAPI()
    response = Mock(status_code=503)
    type(response).text = PropertyMock(side_effect=AssertionError("response body must stay out of logs"))
    with patch.object(api, "_vless_publication", return_value=None), \
            patch("singbox.api.requests.get", return_value=response), \
            patch("singbox.api.requests.put", return_value=response), \
            patch("singbox.api.requests.post", return_value=response), \
            patch("singbox.api.requests.delete", return_value=response):
        assert api.get_proxies() is None
        assert api.get_connections() is None
        assert not api.add_proxy({"name": "synthetic-user"})
        assert not api.remove_proxy("synthetic-user")
        assert not api.close_connection("synthetic-connection")
        assert not api.add_rule({"synthetic": True})
        assert not api.remove_rule("synthetic-rule")
        assert not api.reload()
