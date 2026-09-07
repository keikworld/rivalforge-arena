"""Tests for the long-poll loop.

The loop has no game logic in it at all, so what is worth testing is the three
things a loop like this gets wrong: a poison update that jams it forever, a
blip that kills it, and a shutdown that cannot be asked for.
"""

from __future__ import annotations


from rivalforge.plugins.resilience import PermanentError, TransientError
from rivalforge.telegram.bot import Bot
from rivalforge.telegram.handlers import AnswerCallback, EditMessage, SendMessage


class FakeAPI:
    """Stands in for `TelegramAPI`. Records calls, replays canned answers."""

    def __init__(self, *batches):
        self.batches = list(batches)
        self.offsets = []
        self.sent = []
        self.edited = []
        self.answered = []
        self.webhook_deleted = False

    def get_me(self):
        return {"username": "TestBot"}

    def delete_webhook(self):
        self.webhook_deleted = True

    def get_updates(self, offset=None, *, poll_seconds=None):
        self.offsets.append(offset)
        # An exhausted script polls empty rather than raising: a quiet minute
        # is the normal case and must not look like a failure.
        batch = self.batches.pop(0) if self.batches else []
        # BaseException, not Exception -- KeyboardInterrupt is one of the
        # cases worth scripting and it is not an Exception.
        if isinstance(batch, BaseException):
            raise batch
        return batch

    def send_message(self, chat_id, text, *, keyboard=None):
        self.sent.append((chat_id, text))
        return {"message_id": 1}

    def edit_message_text(self, chat_id, message_id, text, *, keyboard=None):
        self.edited.append((chat_id, message_id, text))

    def answer_callback_query(self, callback_id, *, text="", alert=False):
        self.answered.append((callback_id, text))


class ScriptedHandlers:
    """Returns whatever it was given, or raises."""

    def __init__(self, *results):
        self.results = list(results)
        self.seen = []

    def handle(self, update):
        self.seen.append(update)
        result = self.results.pop(0) if self.results else []
        if isinstance(result, Exception):
            raise result
        return result


class TestStartup:
    def test_start_proves_the_token_works_and_clears_a_webhook(self):
        """A leftover webhook swallows every update, silently and forever."""
        api = FakeAPI()
        bot = Bot(api, ScriptedHandlers())
        assert bot.start()["username"] == "TestBot"
        assert api.webhook_deleted


class TestOffset:
    def test_the_offset_advances_past_a_handled_update(self):
        api = FakeAPI([{"update_id": 5, "message": {}}], [])
        bot = Bot(api, ScriptedHandlers([], []))
        bot.poll_once()
        bot.poll_once()
        assert api.offsets == [None, 6]

    def test_the_offset_advances_past_an_update_that_failed_to_deliver(self):
        """Otherwise one poison update stops the bot for everyone, permanently.

        Telegram redelivers everything below the offset, so an update that made
        us fail must not be asked for again -- and anyone can send one.
        """
        api = FakeAPI([{"update_id": 5, "message": {}}], [])
        handlers = ScriptedHandlers(RuntimeError("boom"))
        bot = Bot(api, handlers)
        bot.poll_once()
        bot.poll_once()
        assert api.offsets == [None, 6]

    def test_an_update_without_an_id_does_not_move_the_offset(self):
        api = FakeAPI([{"message": {}}], [])
        bot = Bot(api, ScriptedHandlers([]))
        bot.poll_once()
        bot.poll_once()
        assert api.offsets == [None, None]

    def test_a_failure_on_one_reply_does_not_stop_the_rest_of_the_batch(self):
        api = FakeAPI([{"update_id": 1}, {"update_id": 2}])
        handlers = ScriptedHandlers(RuntimeError("boom"), [SendMessage(9, "still here")])
        bot = Bot(api, handlers)
        assert bot.poll_once() == 2
        assert api.sent == [(9, "still here")]


class TestActions:
    def test_each_action_reaches_the_matching_api_call(self):
        api = FakeAPI([{"update_id": 1}])
        handlers = ScriptedHandlers(
            [SendMessage(1, "a"), EditMessage(1, 2, "b"), AnswerCallback("cb", "c")]
        )
        Bot(api, handlers).poll_once()
        assert api.sent == [(1, "a")]
        assert api.edited == [(1, 2, "b")]
        assert api.answered == [("cb", "c")]


class TestResilience:
    def test_a_transient_failure_backs_off_and_retries(self):
        slept = []
        api = FakeAPI(TransientError("timeout"), [{"update_id": 1}])
        bot = Bot(api, ScriptedHandlers([]), sleep=slept.append)

        # Stop the loop once the good batch has been served.
        original = api.get_updates

        def get_updates(offset=None, *, poll_seconds=None):
            result = original(offset, poll_seconds=poll_seconds)
            bot.stop()
            return result

        api.get_updates = get_updates
        assert bot.run() == 0
        assert slept == [1.0]

    def test_backoff_grows_rather_than_hammering(self):
        slept = []
        api = FakeAPI(*[TransientError("down")] * 4)
        bot = Bot(api, ScriptedHandlers(), sleep=slept.append)

        original = FakeAPI.get_updates

        def stop_after_four(*a, **k):
            if len(slept) >= 4:
                bot.stop()
            return original(api, *a, **k)

        api.get_updates = stop_after_four
        bot.run()
        assert slept == sorted(slept)
        assert slept[-1] > slept[0]

    def test_it_gives_up_rather_than_retrying_a_dead_endpoint_forever(self):
        api = FakeAPI(*[TransientError("down")] * 100)
        bot = Bot(api, ScriptedHandlers(), sleep=lambda _s: None)
        assert bot.run() == 1

    def test_a_permanent_failure_stops_immediately(self):
        """A revoked token cannot be retried into working."""
        api = FakeAPI(PermanentError("the bot token is wrong or revoked"))
        bot = Bot(api, ScriptedHandlers(), sleep=lambda _s: None)
        assert bot.run() == 1

    def test_the_failure_counter_resets_after_a_good_poll(self):
        slept = []
        api = FakeAPI(TransientError("blip"), [], TransientError("blip"), [])
        bot = Bot(api, ScriptedHandlers(), sleep=slept.append)

        polls = {"n": 0}
        original = FakeAPI.get_updates

        def counted(*a, **k):
            polls["n"] += 1
            if polls["n"] >= 4:
                bot.stop()
            return original(api, *a, **k)

        api.get_updates = counted
        bot.run()
        assert slept == [1.0, 1.0], "backoff must reset after a successful poll"


class TestShutdown:
    def test_stop_ends_the_loop_cleanly(self):
        api = FakeAPI([], [], [])
        bot = Bot(api, ScriptedHandlers())
        bot.stop()
        assert bot.run() == 0
        assert bot.stopping

    def test_ctrl_c_is_a_clean_stop_not_a_traceback(self):
        api = FakeAPI(KeyboardInterrupt())
        bot = Bot(api, ScriptedHandlers())
        assert bot.run() == 0


class TestStartupFailures:
    """A bad token must reach the operator as one readable line.

    A traceback is unhelpful, and it is also a place the request URL -- which
    carries the token -- can escape, since redaction covers logging and not an
    unhandled stack trace.
    """

    def _api_that_fails(self, error):
        api = FakeAPI()

        def get_me():
            raise error

        api.get_me = get_me
        return api

    def test_a_revoked_token_exits_cleanly(self, caplog):
        from rivalforge.telegram.bot import run_forever

        api = self._api_that_fails(PermanentError("the bot token is wrong or revoked"))
        code = run_forever(api, ScriptedHandlers(), install_signal_handlers=False)
        assert code == 1
        assert "revoked" in caplog.text

    def test_an_unreachable_api_exits_cleanly(self, caplog):
        from rivalforge.telegram.bot import run_forever

        api = self._api_that_fails(TransientError("could not reach the Bot API"))
        assert run_forever(api, ScriptedHandlers(), install_signal_handlers=False) == 1
