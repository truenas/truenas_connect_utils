import enum
from typing import Any


class FinalizeResult(enum.Enum):
    SUCCESS = 'success'
    RETRY = 'retry'
    TERMINAL = 'terminal'


RETRYABLE_STATUS_CODES = frozenset({408, 429})
RETRYABLE_400_ERROR_STRINGS = frozenset({'not found'})


def classify_finalize_response(resp: dict[str, Any]) -> tuple[FinalizeResult, str]:
    """Classify a /v1/systems/finalize response dict from request.call().

    Decision matrix:
      - 2xx with 'token' in body              -> SUCCESS
      - 2xx without 'token'                   -> TERMINAL
      - status_code is None                   -> RETRY (network failure)
      - 5xx                                   -> RETRY
      - 408, 429                              -> RETRY
      - 400 with body['error'] == 'not found' -> RETRY (user has not yet
                                                 completed UI registration)
      - any other non-2xx                     -> TERMINAL

    Returns (result, description). `description` is a short human-readable
    string suitable for logging or storing in an initialization_error field.
    """
    status = resp.get('status_code')
    body = resp.get('response') or {}

    if status is None:
        return FinalizeResult.RETRY, resp.get('error') or 'connection error'

    if 200 <= status < 300:
        if isinstance(body, dict) and 'token' in body:
            return FinalizeResult.SUCCESS, ''
        return FinalizeResult.TERMINAL, f'token missing from successful response: {body!r}'

    if 500 <= status < 600:
        return FinalizeResult.RETRY, f'TNC {status}: {body!r}'

    if status in RETRYABLE_STATUS_CODES:
        return FinalizeResult.RETRY, f'TNC {status}: {body!r}'

    if status == 400 and isinstance(body, dict) and body.get('error') in RETRYABLE_400_ERROR_STRINGS:
        return FinalizeResult.RETRY, f'TNC pending registration: {body!r}'

    return FinalizeResult.TERMINAL, f'TNC {status}: {body!r}'
