import inspect
import logging

from collections.abc import Callable

from .exceptions import CallError


logger = logging.getLogger(__name__)


class EventCallback:

    CALLBACKS: list[Callable[[int, str], None]] = []

    def register(self, callback: Callable[[int, str], None]) -> None:
        if not callable(callback):
            raise CallError('Callback must be a callable')

        if len(inspect.signature(callback).parameters) != 2:
            raise CallError(
                'Only 2 argument must be specified for callback with first being progress percentage and '
                'second being percentage text'
            )

        self.CALLBACKS.append(callback)

    def clear(self) -> None:
        self.CALLBACKS = []

    def remove_callback(self, callback: Callable[[int, str], None]) -> None:
        self.CALLBACKS.remove(callback)


event_callbacks = EventCallback()


def send_event(progress: int, text: str) -> None:
    for callback in event_callbacks.CALLBACKS:
        try:
            callback(progress, text)
        except Exception:
            logger.debug('Failed to execute callback', exc_info=True)
