"""Tests for the Bot API client.

The transport is injected, so none of these touch the network. That is the
point of injecting it: the interesting cases -- a 401, a truncated body, a
response the size of a hard drive -- are the ones you cannot arrange against
the real API.
"""

from __future__ import annotations

import json
import urllib.error

import pytest

from rivalforge.plugins.resilience import PermanentError, RetryPolicy, TransientError
from rivalforge.security.redaction import redact
from rivalforge.security.validation import ValidationError
from rivalforge.telegram.api import (
    ALLOWED_UPDATES,
    MAX_MESSAGE_CHARS,
    MAX_RESPONSE_BYTES,
    TelegramAPI,
    TelegramError,
    read_token,
    redact_token,
)

# A structurally valid token that is not a real one. The digits and the letters
# are both made up; nothing here has ever authenticated anything.
TOKEN = "123456789:AAFakeTokenForTestsOnlyNotRealAtAll"  # NOT-A-REAL-SECRET


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, size: int | None = None) -> bytes:
        return self._body if size is None else self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Records requests and replays canned answers."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append((request, timeout))
        answer = self.answers.pop(0) if self.answers else {"ok": True, "result": True}
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, bytes):
            return FakeResponse(answer)
        return FakeResponse(json.dumps(answer).encode("utf-8"))

    @property
    def last_payload(self):
        return json.loads(self.requests[-1][0].data.decode("utf-8"))

    def method_of(self, index: int) -> str:
        return self.requests[index][0].full_url.rsplit("/", 1)[-1]


def api(*answers, **kwargs) -> tuple[TelegramAPI, FakeOpener]:
    opener = FakeOpener(*answers)
    kwargs.setdefault("policy", RetryPolicy(attempts=1, total_timeout=1.0))
    return TelegramAPI(TOKEN, opener=opener, **kwargs), opener


class TestToken:
    def test_the_token_comes_from_the_environment_only(self):
        assert read_token({"RIVALFORGE_TELEGRAM_TOKEN": TOKEN}) == TOKEN
        assert read_token({"TELEGRAM_BOT_TOKEN": TOKEN}) == TOKEN

    def test_a_missing_token_is_a_clear_error(self):
        with pytest.raises(ValidationError):
            read_token({})

    def test_a_malformed_token_fails_at_startup_not_at_the_first_call(self):
        """A quote-wrapped token otherwise shows up as a 404 much later."""
        for bad in (f"'{TOKEN}'", "notatoken", "123:short", ""):
            with pytest.raises(ValidationError):
                read_token({"RIVALFORGE_TELEGRAM_TOKEN": bad})

    def test_an_error_about_the_token_never_contains_it(self):
        try:
            read_token({"RIVALFORGE_TELEGRAM_TOKEN": f"'{TOKEN}'"})
        except ValidationError as exc:
            assert "AAFake" not in str(exc)
        else:  # pragma: no cover
            pytest.fail("expected a ValidationError")

    def test_whitespace_is_stripped_because_that_is_how_it_is_pasted(self):
        assert read_token({"RIVALFORGE_TELEGRAM_TOKEN": f"  {TOKEN}\n"}) == TOKEN


class TestTokenNeverLeaks:
    """The token is the bot. Anything that formats a URL is a place it escapes."""

    def test_the_url_carries_the_token_and_redaction_removes_it(self):
        client, opener = api({"ok": True, "result": {}})
        client.get_me()
        url = opener.requests[0][0].full_url
        assert TOKEN in url  # it has to be there; that is how the API works
        assert TOKEN not in redact_token(url)
        assert TOKEN not in redact(url)

    def test_a_transport_failure_message_is_redacted(self):
        """`URLError` can carry the request URL, and the URL carries the token."""
        client, _ = api(urllib.error.URLError(f"failed for {TOKEN}"))
        with pytest.raises(TransientError) as caught:
            client.get_me()
        assert "AAFakeTokenForTestsOnlyNotRealAtAll" not in str(caught.value)

    def test_a_rejection_description_is_redacted(self):
        client, _ = api({"ok": False, "description": f"bad token {TOKEN}"})
        with pytest.raises(PermanentError) as caught:
            client.get_me()
        assert "AAFakeTokenForTestsOnlyNotRealAtAll" not in str(caught.value)

    def test_the_global_redaction_filter_also_catches_it(self):
        assert TOKEN not in redact(f"POST https://api.telegram.org/bot{TOKEN}/getUpdates")


class TestTransport:
    def test_plain_http_is_refused(self):
        """A plain-HTTP base URL puts the token on the wire in clear text."""
        with pytest.raises(ValidationError):
            TelegramAPI(TOKEN, base_url="http://api.telegram.org")

    def test_loopback_is_allowed_for_a_local_mock(self):
        TelegramAPI(TOKEN, base_url="http://127.0.0.1:8081")

    def test_a_429_is_transient_and_a_400_is_not(self):
        client, _ = api(urllib.error.HTTPError("u", 429, "slow down", {}, None))
        with pytest.raises(TransientError):
            client.get_me()

        client, _ = api(urllib.error.HTTPError("u", 400, "bad request", {}, None))
        with pytest.raises(PermanentError):
            client.get_me()

    def test_a_401_says_the_token_is_wrong(self):
        """"HTTP 401" alone sends people looking in the wrong place."""
        client, _ = api(urllib.error.HTTPError("u", 401, "unauthorized", {}, None))
        with pytest.raises(PermanentError, match="token"):
            client.get_me()

    def test_an_oversized_response_is_refused_rather_than_buffered(self):
        client, _ = api(b"x" * (MAX_RESPONSE_BYTES + 10))
        with pytest.raises(PermanentError, match="oversized"):
            client.get_me()

    def test_a_malformed_body_is_transient(self):
        client, _ = api(b"not json at all")
        with pytest.raises(TransientError):
            client.get_me()

    def test_a_response_that_is_not_an_object_is_refused(self):
        client, _ = api(b"[1, 2, 3]")
        with pytest.raises(TransientError):
            client.get_me()

    def test_every_request_carries_a_timeout(self):
        client, opener = api({"ok": True, "result": {}})
        client.get_me()
        assert opener.requests[0][1] is not None
        assert opener.requests[0][1] > 0


class TestMethods:
    def test_get_updates_asks_only_for_what_it_handles(self):
        """The cheapest way to not mishandle a channel post is to not receive it."""
        client, opener = api({"ok": True, "result": []})
        client.get_updates(offset=7)
        payload = opener.last_payload
        assert payload["allowed_updates"] == list(ALLOWED_UPDATES)
        assert payload["offset"] == 7

    def test_get_updates_waits_longer_than_the_server_side_poll(self):
        """Timing out before Telegram answers turns a quiet minute into an error."""
        client, opener = api({"ok": True, "result": []})
        client.get_updates(poll_seconds=30)
        assert opener.requests[0][1] > 30

    def test_get_updates_discards_anything_that_is_not_an_update(self):
        client, _ = api({"ok": True, "result": ["nonsense", 5, {"update_id": 1}]})
        updates = client.get_updates()
        assert [u["update_id"] for u in updates] == [1]

    def test_get_updates_survives_a_result_that_is_not_a_list(self):
        client, _ = api({"ok": True, "result": {"unexpected": True}})
        assert client.get_updates() == ()

    def test_send_message_disables_link_previews(self):
        """A preview is an outbound fetch of a URL somebody else wrote."""
        client, opener = api({"ok": True, "result": {"message_id": 1}})
        client.send_message(5, "hello")
        assert opener.last_payload["link_preview_options"] == {"is_disabled": True}

    def test_send_message_refuses_text_over_telegrams_limit(self):
        client, _ = api()
        with pytest.raises(TelegramError):
            client.send_message(5, "x" * (MAX_MESSAGE_CHARS + 1))

    def test_a_keyboard_is_sent_as_inline_rows(self):
        client, opener = api({"ok": True, "result": {}})
        client.send_message(5, "hi", keyboard=[[{"text": "a", "callback_data": "b"}]])
        assert opener.last_payload["reply_markup"] == {
            "inline_keyboard": [[{"text": "a", "callback_data": "b"}]]
        }

    def test_editing_to_identical_text_is_not_an_error(self):
        """Telegram calls it an error; it is a no-op everywhere else."""
        client, _ = api({"ok": False, "description": "Bad Request: message is not modified"})
        client.edit_message_text(5, 6, "same")  # must not raise

    def test_a_real_edit_failure_still_raises(self):
        client, _ = api({"ok": False, "description": "Bad Request: chat not found"})
        with pytest.raises(PermanentError):
            client.edit_message_text(5, 6, "text")

    def test_editing_clears_a_stale_keyboard(self):
        """Otherwise a finished match keeps its stance buttons."""
        client, opener = api({"ok": True, "result": {}})
        client.edit_message_text(5, 6, "over")
        assert opener.last_payload["reply_markup"] == {"inline_keyboard": []}

    def test_a_late_callback_acknowledgement_is_not_fatal(self):
        """A callback id expires after about a minute; losing that race is normal."""
        client, _ = api({"ok": False, "description": "query is too old"})
        client.answer_callback_query("abc", text="done")  # must not raise

    def test_callback_text_is_truncated_to_telegrams_limit(self):
        client, opener = api({"ok": True, "result": True})
        client.answer_callback_query("abc", text="x" * 500)
        assert len(opener.last_payload["text"]) == 200

    def test_delete_webhook_is_called_so_polling_can_work(self):
        """A leftover webhook swallows every update, silently and forever."""
        client, opener = api({"ok": True, "result": True})
        client.delete_webhook()
        assert opener.method_of(0) == "deleteWebhook"


class TestOverARealSocket:
    """One test that is not mocked at all.

    Every other test here injects the transport, which is what makes the
    hostile cases reachable -- but it also means the real HTTP path is never
    run. This spins up a Bot API on loopback and drives the actual client
    through it: real socket, real request framing, real JSON on the wire.

    A proxy-free opener is passed in because this environment routes outbound
    HTTP through a proxy that has no business seeing a loopback request. It is
    still `urllib`, still a real connection.
    """

    @pytest.fixture
    def server(self):
        import http.server
        import threading

        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                method = self.path.rsplit("/", 1)[-1]
                length = int(self.headers.get("Content-Length", 0))
                calls.append((method, json.loads(self.rfile.read(length) or b"{}")))
                body = json.dumps(_ANSWERS.get(method, {"ok": True, "result": True}))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *args):
                pass

        _ANSWERS = {
            "getMe": {"ok": True, "result": {"id": 1, "username": "LoopbackBot"}},
            "getUpdates": {"ok": True, "result": [{"update_id": 1}]},
            "sendMessage": {"ok": True, "result": {"message_id": 3}},
        }

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield httpd, calls
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def test_the_real_client_talks_to_a_real_server(self, server):
        import urllib.request

        httpd, calls = server
        host, port = httpd.server_address[:2]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({})).open

        client = TelegramAPI(
            TOKEN,
            base_url=f"http://{host}:{port}",
            timeout=5.0,
            policy=RetryPolicy(attempts=1, total_timeout=10.0),
            opener=opener,
        )

        assert client.get_me()["username"] == "LoopbackBot"
        client.delete_webhook()
        updates = client.get_updates(poll_seconds=0)
        assert [u["update_id"] for u in updates] == [1]
        client.send_message(42, "hello from a real socket")

        methods = [method for method, _ in calls]
        assert methods == ["getMe", "deleteWebhook", "getUpdates", "sendMessage"]
        # And the request really was shaped the way the unit tests assert.
        send = dict(calls)["sendMessage"]
        assert send["chat_id"] == 42
        assert send["link_preview_options"] == {"is_disabled": True}
