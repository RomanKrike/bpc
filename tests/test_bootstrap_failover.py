from __future__ import annotations

import io
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
import bpc_node_enrollment as enrollment  # noqa: E402

A = "https://ru-01.blinpi.ru:8444"
B = "https://ru-02.blinpi.ru:8444"


@pytest.mark.parametrize("failure", [502, 503, 504, "network", "reset"])
def test_bootstrap_fails_over_transport_errors(monkeypatch, failure):
    calls = []

    def open_url(request, **kwargs):
        calls.append(request.full_url)
        if request.full_url.startswith(A):
            if failure == "network":
                raise urllib.error.URLError("unreachable")
            if failure == "reset":
                raise ConnectionResetError("reset")
            raise urllib.error.HTTPError(request.full_url, failure, "temporary", {},
                                         io.BytesIO(b'{"error":"unavailable"}'))
        return io.BytesIO(b'{"ok":true}')

    monkeypatch.setattr(enrollment.urllib.request, "urlopen", open_url)
    response = enrollment.request_json(A, "/v1/nodes/join", {}, controller_urls=[A, B])
    assert response["_controller_url"] == B
    assert calls == [A + "/v1/nodes/join", B + "/v1/nodes/join"]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 410, 422, 429])
def test_terminal_request_failure_does_not_bypass_next_controller(monkeypatch, status):
    calls = []

    def open_url(request, **kwargs):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, status, "terminal", {},
                                     io.BytesIO(b'{"error":"rejected"}'))

    monkeypatch.setattr(enrollment.urllib.request, "urlopen", open_url)
    with pytest.raises(enrollment.EnrollmentError) as error:
        enrollment.request_json(A, "/v1/nodes/join", {}, controller_urls=[B])
    assert error.value.status == status
    assert calls == [A + "/v1/nodes/join"]


@pytest.mark.parametrize("url", ["http://a.b", "https://user:password@a.b", "https://a.b?x=y",
                                 "https://a.b#x", "https://a.b/path", "https://a.b:bad",
                                 "https://a b", "https://"])
def test_invalid_controller_urls_are_rejected(url):
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.normalize_controller_url(url)


def test_heartbeat_retains_bootstrap_pool_if_response_has_no_alternatives(tmp_path, monkeypatch):
    (tmp_path / "identity").mkdir()
    (tmp_path / "identity" / "node.pub").write_text("key")
    record = {"node_id": "a" * 32, "name": "home-01", "credential": "secret",
              "roles": {"site_router": True}, "controller_url": A, "controllers": [A, B]}
    monkeypatch.setattr(enrollment, "local_services", lambda _, role_config=None: {})
    monkeypatch.setattr(enrollment, "request_json", lambda *a, **k: {
        "_controller_url": B, "roles": {"site_router": True}, "config": {"controllers": []},
    })
    enrollment.send_heartbeat(tmp_path, record)
    restored = enrollment.enrolled_state(tmp_path)
    assert restored["controller_url"] == B
    assert set(restored["controllers"]) == {A, B}


def test_controller_promotion_waits_for_catchup_deadline(tmp_path, monkeypatch):
    import bpc_control_state as state

    (tmp_path / "cluster").mkdir()
    (tmp_path / "cluster/controller.json").write_text("{}")
    monkeypatch.setattr(state, "_local_token", lambda _: "a" * 64)
    observed = []

    def open_url(request, **kwargs):
        observed.append(kwargs["timeout"])
        return io.BytesIO(b'{"ok":true,"state":"voter"}')

    monkeypatch.setattr(state.urllib.request, "urlopen", open_url)
    assert state.add_controller_member(tmp_path / "control", {})["state"] == "voter"
    assert observed == [90]
